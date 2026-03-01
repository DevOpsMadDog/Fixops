# ALdeci — Objection Handling Playbook

> **Version**: 1.0 — Sprint 2 (Enterprise Demo)
> **Updated**: 2026-03-01
> **Author**: Sales Engineer Agent
> **Source**: CTEM+ Identity (docs/CTEM_PLUS_IDENTITY.md), Competitive Analysis (docs/COMPETITIVE_ANALYSIS_GROK_RESPONSE.md)

---

## Tier 1: "We Already Have..." Objections

### "We already have Snyk"

**Response**: "Great — keep it. ALdeci ingests Snyk output AND runs our own 8 native scanners on top. You get MORE coverage, not less. Day 1, we normalize your Snyk findings into our knowledge graph, correlate them with data from your other tools, verify exploitability with MPTE, and auto-generate fixes. Snyk tells you what's wrong. ALdeci tells you what to DO about it — and does it for you."

**Proof Point**: Upload a Snyk JSON report → `POST /api/v1/scanner-ingest/upload` → watch it flow through Brain Pipeline in real-time.

**Differentiator**: Snyk has 2 fix types (dependency update, patch). ALdeci has 10 fix types including CODE_PATCH, CONFIG_HARDENING, SECRET_ROTATION, WAF_RULE, CONTAINER_FIX.

---

### "We already have Semgrep"

**Response**: "Semgrep is an excellent SAST engine. ALdeci has its own SAST engine too — 465 LOC of multi-language pattern matching. But here's the thing: when your Semgrep finds a SQL injection, does it PROVE it's exploitable? Does it auto-generate a parameterized query fix? Does it create a signed compliance evidence bundle? ALdeci does all of that. We complement Semgrep, and we can replace it if you need to go air-gapped."

**Proof Point**: Run native SAST → `POST /api/v1/sast/scan/code` → then MPTE verify → `POST /api/v1/mpte/verify`.

---

### "We already have Wiz / Prisma Cloud"

**Response**: "Wiz is cloud-native. ALdeci normalizes Wiz's cloud findings AND adds layers Wiz can't: MPTE exploit verification, multi-LLM consensus decisions, AutoFix code patches, and cryptographically signed evidence. We also work air-gapped — Wiz and Prisma require internet connectivity. For your cloud security team, ALdeci is the decision layer that sits above Wiz."

**Proof Point**: Show the 10 security tool connectors including Wiz and Prisma Cloud in `core/security_connectors.py`.

---

### "We already have Qualys / Tenable / Rapid7"

**Response**: "Those are great vulnerability scanners. ALdeci doesn't replace your scanner — it makes your scanner 10x more useful. We ingest from ALL of them simultaneously, deduplicate (11,300 → 340 actionable cases), correlate via knowledge graph, and prioritize by business impact — not just CVSS score. Your scanner finds things. ALdeci decides what to do about them."

**Proof Point**: `GET /api/v1/analytics/dashboard/overview` showing 97% noise reduction.

---

## Tier 2: "How Is This Different?" Objections

### "How is this different from Vulcan Cyber / Seemplicity / ArmorCode?"

**Response**: "Three things no aggregator has:

1. **We ARE the scanner** — 8 built-in engines work air-gapped. Vulcan/Seemplicity/ArmorCode are pure aggregators with zero scanning capability. If your scanner goes down, they go dark. We keep running.

2. **MPTE Exploit Verification** — 19-phase micro-pentesting that PROVES exploitability. Aggregators just trust the scanner's severity. We verify it independently.

3. **12-Step Brain Pipeline** — Not just dedup + prioritize. We build a knowledge graph, run multi-LLM consensus, generate fixes, and produce signed evidence. Aggregators stop at 'prioritize and ticket.'"

**Kill Shot**: "Ask Vulcan to scan your code without Snyk. They can't. We can."

---

### "How is AutoFix different from GitHub Copilot / Snyk Fix?"

**Response**: "Three differences:

1. **10 fix types** vs Snyk's 2 (dependency update, patch). We do CODE_PATCH, CONFIG_HARDENING, SECRET_ROTATION, INPUT_VALIDATION, OUTPUT_ENCODING, WAF_RULE, IAC_FIX, PERMISSION_FIX, CONTAINER_FIX, and DEPENDENCY_UPDATE.

2. **Confidence-based auto-apply**. HIGH confidence (>85%) fixes auto-apply and create PRs. MEDIUM gets human review. LOW is suggestion-only. Snyk and Copilot don't have confidence-gated automation.

3. **Post-deploy verification**. After the fix deploys, ALdeci re-scans to confirm the vulnerability is actually gone. If not, it rolls back. No other tool does this."

---

### "Isn't multi-LLM consensus just calling 3 APIs? We can build that ourselves."

**Response**: "Calling 3 APIs is 5% of the work. The other 95% is: prompt engineering per vulnerability type, confidence calibration across models that disagree differently, fallback to deterministic scoring when LLMs are unavailable, self-hosted inference for air-gapped deployments (Llama 3.1 70B assuming 4 expert roles), and the 85% agreement threshold that eliminates single-model hallucination. We've invested 2,000+ LOC in this engine. Building it yourself means 6 months of ML engineering."

---

## Tier 3: Deployment & Security Objections

### "What about air-gapped environments?"

**Response**: "ALdeci was built air-gap-first. Our 8 native scanners work with zero internet. Our self-hosted AI runs on Llama 3.1 70B via vLLM or Ollama — zero API tokens, data never leaves your network. Our knowledge graph is SQLite-backed — no cloud database dependency. The entire platform runs on commodity hardware in a Docker container. Government and defense customers love this."

**Proof Point**: `docker compose up` with network disabled → run full CTEM+ loop → `bash .claude/team-state/sales/demo-scripts/ctem-full-loop.sh`

---

### "What about data privacy / sovereignty?"

**Response**: "Your data never leaves your environment. ALdeci runs on-prem or in your VPC — we have no SaaS dependency. Scan results, evidence bundles, and knowledge graph data are stored locally in SQLite. If you use cloud LLMs (optional), the prompts contain finding metadata only — no source code is sent. For maximum security, use our self-hosted AI and nothing ever leaves your infrastructure."

---

### "Are you SOC2 certified?"

**Response**: "We're SOC2-mapped — our compliance engine generates SOC2 evidence bundles covering all 47 controls. Our own SOC2 Type II audit is scheduled for Phase 3 (Q3 2026). In the meantime, we provide the tooling to help YOU achieve SOC2 compliance, with cryptographically signed evidence that auditors trust."

**Honest caveat**: Don't claim "SOC2 certified" — say "SOC2-mapped evidence generation."

---

### "How do you handle secrets / credentials?"

**Response**: "ALdeci has a dedicated secrets scanner (775 LOC, 200+ patterns) that detects leaked credentials, API keys, and tokens. The SECRET_ROTATION fix type auto-generates rotation scripts. For your credentials in ALdeci itself, we use environment variables — API keys are never stored in code or database."

---

## Tier 4: Technical Deep-Dive Objections

### "Your SAST engine is pattern-matching, not AST-based."

**Response**: "Correct — our SAST engine uses multi-language pattern matching with taint analysis. For enterprise-grade AST-based scanning, you'd use your existing Semgrep or Checkmarx, and ALdeci ingests their output. Our native SAST is the air-gapped fallback — it catches the top 50 vulnerability patterns (CWE top 25 + OWASP top 10) without any external dependency. Think of it as the 80/20 rule: we catch 80% of critical issues with a lightweight, always-available engine."

**Honest caveat**: Don't overclaim SAST sophistication. Our value is in the pipeline, not the scanner.

---

### "How does the knowledge graph scale?"

**Response**: "Currently SQLite-backed with in-memory graph construction. For the demo and POC phase, this handles up to 100K nodes efficiently. For production scale (1M+ findings), we have the FalkorDB integration ready — a Redis-based graph database that handles billions of edges. The migration path is automatic."

---

### "What's your SLA / uptime guarantee?"

**Response**: "ALdeci is an on-prem platform — your uptime is your infrastructure's uptime. We don't have a cloud service with SLA. What we do have: Docker Compose for repeatable deployments, health check endpoints for every service (`/health`), and the Agent Doctor system that monitors and auto-heals the platform."

---

## Tier 5: Competitive Battle Cards

### vs. Snyk

| Dimension | Snyk | ALdeci |
|-----------|------|--------|
| **Scanning** | Own SAST/SCA/Container/IaC | 8 native engines + ingests Snyk |
| **Fix types** | 2 (dependency, patch) | 10 types with confidence scoring |
| **Exploit verification** | No | 19-phase MPTE |
| **Knowledge graph** | No | Full attack path analysis |
| **Air-gapped** | No | Full offline capability |
| **MCP gateway** | No | 650+ auto-discovered tools |
| **Compliance evidence** | Basic | Cryptographically signed bundles |

**Win scenario**: Customer has multiple scanners + needs verification + compliance.

### vs. Wiz

| Dimension | Wiz | ALdeci |
|-----------|-----|--------|
| **Focus** | Cloud-native | Application security (multi-environment) |
| **Scanning** | Cloud posture, container, IaC | 8 native + cloud via connectors |
| **Code fixes** | No | 10 AutoFix types |
| **Exploit verification** | Attack path (graph-based) | MPTE (active verification) |
| **Air-gapped** | No | Full offline |
| **AI consensus** | No | Multi-LLM with 85% threshold |
| **Evidence signing** | No | RSA-SHA256 + quantum-ready |

**Win scenario**: Regulated industry + air-gapped + needs code-level remediation.

### vs. ArmorCode / Vulcan Cyber / Seemplicity

| Dimension | Aggregators | ALdeci |
|-----------|-------------|--------|
| **Own scanners** | No | 8 native engines |
| **MPTE verification** | No | 19-phase exploit proof |
| **AutoFix** | Ticket routing only | AI-generated code patches |
| **Knowledge graph** | Basic correlation | Full graph with attack paths |
| **Air-gapped** | No | Full offline |
| **MCP protocol** | No | 650+ tools for AI agents |

**Kill Shot**: "Can they scan your code without an external scanner? No. We can."

### vs. DeepAudit

| Dimension | DeepAudit | ALdeci |
|-----------|-----------|--------|
| **PoC Verification** | 49 real CVEs sandbox tested | MPTE 19-phase engine |
| **Pipeline** | Scan → Verify | 12-step Brain Pipeline |
| **Compliance** | Limited | Full framework mapping + evidence |
| **Fix generation** | No | 10 AutoFix types |
| **Knowledge graph** | No | Full attack path analysis |

**Positioning**: "Same sandbox PoC concept as DeepAudit, but with a full 12-step pipeline, enterprise compliance, and automated remediation on top."

---

## Pricing Objections

### "That's expensive for a startup"

**Response**: "Let me show you the math. Average enterprise spends $4,200 per vulnerability fixed. ALdeci reduces that to $890 — a 79% reduction. With 340 actionable cases per year, that's $110K in annual savings. Professional tier is $3-5K/month. ROI positive in 2 months."

### "Can we get a pilot / POC?"

**Response**: "Absolutely. 2-week POC, free of charge. We'll connect to your existing scanners, ingest your real data, and show you the noise reduction and verification results. Success criteria agreed upfront — no surprises."

---

*Updated by Sales Engineer Agent — 2026-03-01. Source truth: docs/CTEM_PLUS_IDENTITY.md, docs/COMPETITIVE_ANALYSIS_GROK_RESPONSE.md*
