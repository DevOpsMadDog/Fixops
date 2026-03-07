# Urgent Intelligence — ALdeci

**Last Updated**: 2026-03-07 22:20 (v8 — Post-Demo Day 1 + Codex Security Launch)
**Author**: ai-researcher

---

## ACTIVE ALERTS

### 🔴 RED: OpenAI Codex Security — LAUNCHED Mar 6 (Evolved from Aardvark)
- **What**: Full product launch (research preview). GPT-5.2-Codex model. Project-specific threat models, agentic vuln hunting, sandbox validation, architectural fixes. 50% FP reduction, 90% severity over-report reduction. 800 critical + 10,500 high findings in beta. Free first month for Enterprise/Business/Edu.
- **Threat level**: CRITICAL. Directly competes with V5 MPTE + V3 AutoFix. Launched SAME DAY as our Enterprise Demo.
- **ALdeci positioning**: Codex Security = single-model, single-repo scanning. ALdeci = Multi-LLM Consensus (3+), org-wide CTEM pipeline, air-gapped, MPTE-verified, FAIL engine.
- **Message**: *"OpenAI scans repos. We orchestrate security postures."*
- **Action**:
  1. marketing-head: Build ALdeci vs Codex Security comparison for RSA
  2. sales-engineer: Add Codex Security differentiation to objection handling
  3. backend-hardener: Ensure MPTE demo is compelling (proves exploitability — Codex doesn't)
- **Sources**: [Bloomberg](https://www.bloomberg.com/news/articles/2026-03-06/openai-releases-ai-agent-security-tool-for-research-preview), [Axios](https://www.axios.com/2026/03/06/openai-codex-security-ai-cyber), [OpenAI](https://openai.com/index/introducing-gpt-5-2-codex/)

### 🔴 RED: Triple CVSS 10.0 Week (Mar 4-7)
- **What**: Three perfect-10 CVEs plus 12 more critical vulns in 4 days:
  - CVE-2026-20079: Cisco FMC auth bypass → script execution → root (unauthenticated)
  - CVE-2026-20131: Cisco FMC Java deser → RCE as root (unauthenticated)
  - CVE-2026-29000: pac4j-jwt auth bypass — forge admin tokens with RSA public key (PoC available)
- **Threat level**: HIGH for industry. No known exploitation yet for Cisco. PoC exists for pac4j.
- **ALdeci positioning**: "Your scanner found them. Now what? ALdeci decides."
- **Action**:
  1. threat-architect: Add Cisco FMC + pac4j-jwt to threat feed demo data
  2. backend-hardener: Build pac4j-jwt MPTE demo for RSA (PoC available for sandbox)
  3. data-scientist: Update Knowledge Graph with these attack vectors
- **Sources**: [Arctic Wolf](https://arcticwolf.com/resources/blog/cve-2026-20079-cve-2026-20131/), [BleepingComputer](https://www.bleepingcomputer.com/news/security/cisco-warns-of-max-severity-secure-fmc-flaws-giving-root-access/), [CIS](https://www.cisecurity.org/advisory/a-vulnerability-in-pac4j-jwt-jwtauthenticator-could-allow-for-authentication-bypass_2026-019)

### 🔴 RED: Anthropic–Pentagon Crisis — Renegotiating
- **Status**: Amodei back at DoD negotiating table (Mar 5). Legal challenge possible. 900+ tech employees signed open letter supporting Anthropic. Altman admits deal "looked opportunistic."
- **ALdeci angle**: Air-gapped deployment (V9) = no dependency on ANY cloud AI provider's government standing.
- **Message**: "When the Pentagon blacklists your AI vendor, ALdeci keeps running."
- **Sources**: [CNBC](https://www.cnbc.com/2026/03/05/anthropic-pentagon-ai-deal-department-of-defense-openai-.html), [TechCrunch](https://techcrunch.com/2026/03/05/anthropic-ceo-dario-amodei-could-still-be-trying-to-make-a-deal-with-pentagon/)

### 🔴 RED: AWS Security Agent — Multi-Agent Automated Pen Testing
- Multi-agent architecture for automated pen testing. Feb 25: shared VPC support.
- **Threat**: HIGH for V5 MPTE — but AWS-ONLY. ALdeci = cloud-agnostic + air-gapped.
- **Message**: *"AWS tests AWS. ALdeci tests everything."*

### 🔴 RED: RSA 2026 Innovation Sandbox — 16 DAYS (Mar 23)
- 10 finalists, $5M each. 6/10 AI-security. No finalist occupies Decision Intelligence layer — ALdeci's category is OPEN.
- **Action**: Pre-RSA competitive matrix by March 20.
- **Sources**: [RSAC](https://www.rsaconference.com/usa/programs/innovation-sandbox)

### 🔴 RED: Wiz/Google $32B Closing End of March — "Switzerland" Peak
- EU unconditional clearance (Feb 10). All major regulators done. Mid-to-end March close.
- **Message**: "Google just bought your security vendor. What happens to your roadmap?"

---

## 🟡 MONITOR — ACT THIS WEEK

### Endor Labs AURI — Closest Competitor to Brain Pipeline
- Launched Mar 3. Agentic reasoning + deterministic analysis. Full-stack reachability.
- Monitor adoption. We differentiate via MPTE, FAIL, multi-LLM, air-gapped.

### Semgrep Scale Narrative — RSA Prep
- 5.3M AI triage decisions, 95% agreement, 740K auto-fixes. 18K orgs.
- We need post-demo metrics to compete on scale claims at RSA.

### Claude Opus 4.6 Firefox CVEs — Validation
- 22 CVEs in Firefox (14 HIGH) from 6,000 C++ files in 2 weeks.
- Validates AI-powered security auditing. Supports our V5 narrative.
- Message: "Claude finds bugs. ALdeci proves they're exploitable."

### NIST Agentic AI Security — RFI Deadline Mar 9
- Deadline in 2 days. Comment if possible.

### vLLM/SGLang for Air-Gap — Sprint 3 Priority
- SGLang 16,200 TPS > vLLM 12,500 TPS (29% faster). Recommend SGLang.
- Pentagon crisis makes self-hosted LLM THE differentiator.

---

## 🟢 TRACKING — NO IMMEDIATE ACTION

- Snyk Credentials Manager (Mar 6) — table-stakes feature
- Checkmarx + Archipelo partnership (Mar 3) — struggle signal
- CrowdStrike Day Zero Summit (call for papers)
- Tenable EXPOSURE 2026 conference — exposure management positioning
- MCP Security Crisis — 30 CVEs, 36.7% SSRF exposure (ongoing)
- Shadow AI: 47% using GenAI via personal accounts
- Claude Code Security (Feb 20) — 500+ zero-days, market disruption

---

## ✅ RESOLVED (Archive)
- ~~Enterprise Demo (Mar 6)~~ — COMPLETED
- ~~CrowdStrike Q4 Earnings (Mar 3)~~ — Beat estimates, outlook light
- ~~DEMO-010 Knowledge Graph seed~~ — COMPLETED (73 nodes, 110 edges)
- ~~Claude AI Weaponized in Mexico~~ — Tracked, messaging integrated
- ~~n8n CVE-2026-21858~~ — Tracked, validates AI toolchain attack surface

---

*Updated 2026-03-07 EVENING by AI Research Agent. Next review: 2026-03-08 AM.*
