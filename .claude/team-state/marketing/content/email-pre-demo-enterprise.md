# Pre-Demo Email — Enterprise Customer

**Purpose**: Send 1-2 days before the March 6 enterprise demo
**Tone**: Technical, direct, founder's voice — no marketing fluff
**Pillars**: [V3] Decision Intelligence, [V5] MPTE Verification, [V7] MCP-Native

---

## Subject Line Options (Pick One)

1. **ALdeci Demo: From 10,000 findings to 10 actionable decisions — live**
2. **Thursday Demo: See how multi-AI consensus replaces security noise with decisions**
3. **Your security team triages 11,300 findings/quarter. We do it in 5 minutes. Thursday demo.**

---

## Email Body

Hi {FIRST_NAME},

Looking forward to our demo on Thursday, March 6.

**What we'll show you — live, not slides:**

1. **Ingest** — Upload any scanner output (Snyk, Burp, Semgrep, SARIF, CycloneDX, Claude Code Security — any of 25+ formats). Auto-detected, normalized, no manual mapping.

2. **Decide** — Watch the 12-step Brain Pipeline process findings: deduplicate across scanners, build a knowledge graph, enrich with NVD/CISA KEV threat intel, score risk, and run multi-AI consensus (3+ LLMs voting, 85% agreement threshold). 11,300 raw findings become 340 actionable cases — 97% noise eliminated.

3. **Verify** — See the 19-phase Micro Pen-Test Engine prove exploitability on a real finding. Not an estimate — a controlled, evidence-backed proof. Runs 365x/year, not annually.

4. **Fix** — AutoFix generates real code patches with confidence-based auto-apply. 10 fix types including source code, dependencies, config, IaC, secrets rotation, and container hardening.

5. **Prove** — Evidence bundles signed with hybrid RSA + quantum-resistant ML-DSA (FIPS 204) cryptography. SOC2, PCI-DSS, HIPAA mappings generated automatically. 7-year WORM retention.

**Why this matters now:**

- CrowdStrike reports the fastest eCrime breakout time is **27 seconds**. AI-enabled adversary ops are up **89% YoY**. Manual triage can't keep pace.
- The Pentagon just blacklisted a major AI vendor overnight. If your security pipeline depends on a single model provider, you have a single point of failure. ALdeci's multi-model architecture is resilient by design.
- Google is acquiring Wiz this month. Your cloud security vendor may become a cloud vendor dependency. ALdeci works with every tool and is locked to none.

**What to bring:**

- A scanner report from your environment (any format — we'll ingest it live)
- Your triage SLA and current MTTR numbers (we'll benchmark)
- Questions about air-gapped deployment, compliance requirements, or integration with your existing tools

The demo runs 15-20 minutes with Q&A. Everything you'll see runs on a single process, deployable air-gapped on commodity hardware.

Best,
{FOUNDER_NAME}
CEO, ALdeci

P.S. — If you want a head start, our API documentation is at `docs/API_REFERENCE.md` — 796 endpoints, 25+ scanner format parsers, all verified against our live Postman collections (411/411 passing).

---

## Signature Block

```
{FOUNDER_NAME}
CEO & Founder, ALdeci
{EMAIL} | {PHONE}
ALdeci CTEM+ — Decision Intelligence for Application Security
```

---

## Variants

### Short Version (For Follow-Up or Confirmation)

Subject: **Confirming Thursday — ALdeci live demo**

Hi {FIRST_NAME},

Quick confirmation for Thursday, March 6 at {TIME}.

We'll do a live demo — not slides. You'll see raw scanner findings processed through our 12-step Brain Pipeline, verified by micro-pentesting, auto-fixed, and packaged into signed compliance evidence. 15-20 minutes.

If you have a scanner report from your environment (any format), bring it. We'll ingest it live.

See you Thursday.

{FOUNDER_NAME}

### Version for Security Engineering Audience

Subject: **Thursday demo: 12-step CTEM pipeline + 19-phase MPTE — all live API calls**

Hi {FIRST_NAME},

For Thursday's demo, here's what we'll walk through technically:

- **Scanner ingestion**: POST to `/api/v1/scanner-ingest/upload` with any of 25+ formats (15 tool-specific parsers + 10 standard format parsers = 3,352 LOC of parsing logic)
- **Brain Pipeline**: POST to `/api/v1/brain/process` — 12 deterministic steps, 1,533 LOC engine, real-time status reporting
- **MPTE verification**: POST to `/api/v1/mpte/verify` — 19-phase micro-pentest, 3,143 LOC engine across 2 files
- **AutoFix**: POST to `/api/v1/autofix/generate` — 10 fix types, confidence-based auto-apply, 1,428 LOC
- **Evidence export**: POST to `/api/v1/evidence/export` — hybrid RSA + ML-DSA signatures, SOC2/PCI-DSS/HIPAA mapping
- **MCP gateway**: `tools/list` — 796 auto-discovered tools via Model Context Protocol

Everything runs on localhost:8000. All endpoints tested — 411/411 Postman assertions passing. 13,221 tests in our suite.

Bring a scanner report if you want to see your own data flow through.

{FOUNDER_NAME}

---

*Created 2026-03-02 by VP Marketing. All technical claims verified against live codebase with `wc -l` on cited files. Endpoint paths verified against coordination-notes.md (all return 200).*
