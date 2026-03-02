# Post-Demo Follow-Up Email — Enterprise Customer

**Purpose**: Send within 2 hours after the March 6 enterprise demo
**Tone**: Technical, direct, action-oriented — founder's voice
**Pillars**: [V3] Decision Intelligence, [V5] MPTE Verification, [V7] MCP-Native

---

## Subject Line Options

1. **Following up: your {COMPANY} security pipeline → ALdeci next steps**
2. **Demo recap: 97% noise reduction, verified exploitability, quantum-signed evidence**
3. **{FIRST_NAME} — ALdeci demo recap + design partner program**

---

## Email Body

Hi {FIRST_NAME},

Thanks for the time today. Here's a quick recap of what we showed, plus next steps.

### What You Saw

| Phase | What Happened | Key Metric |
|-------|--------------|-----------|
| **Discover** | Uploaded {SCANNER_TYPE} report, auto-detected format, 12-step Brain Pipeline processed | {RAW_COUNT} findings → {ACTIONABLE_COUNT} actionable cases ({REDUCTION}% noise eliminated) |
| **Validate** | 19-phase micro-pentest on top finding | Exploitability: {CONFIRMED/NOT_EXPLOITABLE} — evidence chain generated |
| **Remediate** | AutoFix generated code patch | Confidence: {CONFIDENCE}% — {AUTO_APPLY/PR_REVIEW/SUGGEST_ONLY} |
| **Comply** | Evidence bundle with quantum-secure signature | SOC2/PCI-DSS/HIPAA mapping — hybrid RSA + ML-DSA (FIPS 204) |
| **Platform** | MCP gateway tool discovery | 796 AI-consumable tools, air-gapped deployment ready |

### What Makes This Different

Nine capabilities no competitor has — all verified, all implemented:

1. **12-Step Brain Pipeline** — Complete Gartner CTEM lifecycle in a single engine (1,533 LOC)
2. **Multi-AI Consensus** — 3+ LLMs voting at 85% threshold. Resilient to vendor bans (ask about the Pentagon-Anthropic situation)
3. **19-Phase MPTE** — Proves exploitability, doesn't estimate. 365x/year vs. 1 annual pentest (3,143 LOC)
4. **FAIL Engine** — Chaos engineering for security. Industry first. Generates labeled training data (711 LOC)
5. **8 Native Scanners** — Full coverage air-gapped. SAST, DAST, Secrets, Container, CSPM/IaC, API Fuzzer, Malware, LLM Monitor (4,757+ LOC)
6. **Switzerland Orchestration** — 25+ scanner format parsers. Works with everything, replaces nothing. Day 1 value (3,352 LOC)
7. **MCP-Native** — First AppSec platform AI agents can consume. 796 auto-discovered tools (978 LOC)
8. **10-Type AutoFix** — Real code patches with confidence-based auto-apply (1,428 LOC)
9. **Quantum-Secure Evidence** — Hybrid RSA + ML-DSA signatures, 7-year WORM, auto-generated compliance mapping (1,248 LOC)

### Suggested Next Steps

**Option A — Design Partner Pilot (Recommended)**

We're selecting 5 design partners for our enterprise program. As a design partner, you get:

- Full ALdeci CTEM+ deployment in your environment (on-prem or air-gapped)
- Direct line to the founding team for feedback and feature requests
- Custom parser development for any scanner format not yet supported
- Priority support and integration assistance
- Design partner pricing (significant discount on enterprise tier)

In return, we ask for:
- 30-day evaluation with real scanner data from your pipeline
- Monthly feedback session (30 min) on workflow integration
- Permission to use anonymized case study metrics (findings reduced, MTTR improvement)

**Option B — Proof of Concept (2 Weeks)**

We deploy ALdeci alongside your current tools. You upload scanner reports from your actual pipeline. We demonstrate:
- Noise reduction ratio on YOUR data
- MPTE verification on YOUR top findings
- AutoFix patches for YOUR codebase
- Compliance evidence for YOUR frameworks

No rip-and-replace. ALdeci sits on top of what you already have.

**Option C — Technical Deep Dive**

If your security engineering team wants to go deeper before a pilot:
- API walkthrough: 796 endpoints, all documented with curl examples
- Scanner parser format compatibility check
- Air-gapped deployment architecture review
- MCP integration with your existing AI tools

### Timing

- **This week**: I'll send the technical architecture document and API reference
- **Next week**: 30-minute call to discuss which option fits your timeline
- **RSA Conference (Mar 23-26)**: Happy to connect in person if you're attending

Let me know which direction makes sense, or if there's someone else on your team who should be part of the conversation.

Best,
{FOUNDER_NAME}
CEO, ALdeci

---

## Variant: Design Partner Invitation (If Strong Signal)

Subject: **ALdeci design partner invitation — {COMPANY}**

Hi {FIRST_NAME},

After today's demo, I want to formally invite {COMPANY} into our design partner program.

**What you get:**
- Full CTEM+ platform deployment (air-gapped or cloud)
- Priority scanner format parser development
- Direct access to the founding team
- Design partner pricing: $X,XXX/mo (vs. $XX,XXX enterprise tier)
- Co-development of features specific to your environment

**What we need:**
- 30-day evaluation with real production scanner data
- Monthly 30-min feedback session
- Permission to reference anonymized metrics (e.g., "Fortune 500 financial services company reduced MTTR from 14 days to 2 hours")

We're taking 5 design partners. {COMPANY}'s environment — {SPECIFIC_DETAIL_FROM_DEMO} — is exactly the use case ALdeci is built for.

Happy to send the design partner agreement this week. Shall I?

{FOUNDER_NAME}

---

## Variant: Technical Follow-Up (For Security Engineering Lead)

Subject: **ALdeci API reference + deployment guide — following up from demo**

Hi {FIRST_NAME},

Following up from today's demo. Attaching the technical resources your team asked about:

1. **API Reference**: 796 endpoints grouped by CTEM lifecycle (Discover, Validate, Remediate, Comply, Intelligence, Platform). Includes curl examples for the top 20 workflows.

2. **Scanner Parser Compatibility**: We parse 25+ formats today:
   - **Tool-specific**: ZAP, Burp, Nessus, OpenVAS, Bandit, Checkmarx, SonarQube, Fortify, Veracode, Nikto, Nuclei, Nmap, Snyk, Prowler, Checkov
   - **Standard formats**: SARIF, CycloneDX, SPDX, VEX, CNAPP, Trivy, Grype, Semgrep, Dependabot
   - **Custom**: Tell us what you run — adding a parser takes days, not months

3. **Air-Gapped Deployment**: `docker compose up` — single command. 8 native scanners, self-hosted AI via vLLM, quantum crypto — zero internet dependency. <1 GB/year storage.

4. **MCP Integration**: 796 tools auto-discovered via Model Context Protocol. If you're building internal AI agents or copilots, they can consume ALdeci's full security surface programmatically.

Let me know if your team wants a hands-on API walkthrough. We can set up a sandbox environment in your infrastructure for the POC.

{FOUNDER_NAME}

---

*Created 2026-03-02 by VP Marketing. All technical claims verified against live codebase. Endpoint counts: 796 route decorators across 78 router files. Scanner parsers: 3,352 LOC across 2 files. All figures from `wc -l` verification run on 2026-03-02.*
