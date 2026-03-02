# ALdeci CTEM+ — 5-Minute Enterprise Demo Script

**Purpose**: Guided narration for the March 6 enterprise demo
**Duration**: 5 minutes (expandable to 15 with Q&A per persona)
**Pillars**: [V3] Decision Intelligence, [V5] MPTE Verification, [V7] MCP-Native

---

## OPENING (30 seconds)

**[Screen: Terminal / ALdeci API ready]**

> "Your team runs multiple security scanners. Each one produces thousands of findings. Most are noise. The real question isn't 'what are the vulnerabilities?' — it's 'what should we DO about them?'
>
> ALdeci answers that question. In the next 5 minutes, I'll show you the complete journey: from raw scanner output to verified, auto-fixed, compliance-ready results. No slides. All live."

---

## ACT 1: DISCOVER — Ingest & Triage (90 seconds)

**[Screen: Terminal — upload scanner output]**

> "Step one: we ingest findings. I'm going to upload a real scanner report — this is Snyk output, but it could be any of 25+ formats: Burp, ZAP, Nessus, Checkmarx, Semgrep, SARIF, CycloneDX — even Claude Code Security output."

**[Run: POST /api/v1/scanner-ingest/upload with sample report]**

> "ALdeci auto-detects the scanner format and normalizes every finding into our Universal Finding Format. No manual mapping, no format conversion."

**[Run: POST /api/v1/brain/process — show 12-step pipeline execution]**

> "Now the Brain Pipeline runs — 12 steps. Watch: normalize, deduplicate across scanners, build the knowledge graph, enrich with threat intel from NVD and CISA KEV, score risk, apply your policies, run multi-AI consensus...
>
> 247 raw findings just became 12 actionable cases. That's 95% noise eliminated — automatically."

**[Show: Knowledge graph with blast radius — Log4Shell spreading to 41 nodes]**

> "The knowledge graph shows how findings connect. See this Log4Shell instance? It reaches 41 nodes with a 9.1x risk multiplier. That's not just 'high severity' — that's verified blast radius."

---

## ACT 2: VALIDATE — Prove Exploitability (90 seconds)

**[Screen: MPTE verification UI]**

> "The industry's dirty secret: most 'critical' findings aren't exploitable in your environment. Competitors estimate. ALdeci proves."

**[Run: POST /api/v1/mpte/verify — trigger 19-phase micro-pentest on a finding]**

> "I'm launching a micro-pentest against the top finding. The MPTE runs 19 deterministic phases: reconnaissance, port enumeration, vulnerability identification, exploit selection, controlled exploitation — with safety bounds — evidence collection, and cleanup.
>
> This runs 365 times a year, automatically. Your annual pentest costs $50K and happens once. This is continuous."

**[Show: MPTE result — exploitability CONFIRMED with evidence chain]**

> "Verdict: CONFIRMED exploitable. Here's the evidence chain — recon results, the exploit path, the payload that worked, the response proving exploitation. This isn't an estimate. This is proof."

---

## ACT 3: REMEDIATE — Auto-Fix (60 seconds)

**[Screen: AutoFix UI]**

> "Now the critical part: fixing it. I'm triggering AutoFix on this verified finding."

**[Run: POST /api/v1/autofix/generate — show fix generation]**

> "ALdeci generates a code patch — real code, not a suggestion. This is a CODE_PATCH fix type — one of 10 types including dependency updates, config hardening, IaC fixes, secret rotation, and more.
>
> Confidence score: 87% — that's HIGH. At our thresholds, this auto-merges and creates a PR automatically. MEDIUM confidence (60-85%) creates a PR for review. LOW (<60%) suggests only.
>
> Futurum Group asked 'who patches the zero-days before attackers arrive?' This is the answer."

---

## ACT 4: COMPLY — Evidence for Auditors (45 seconds)

**[Screen: Evidence export]**

> "Every decision, every scan, every fix — packaged into a cryptographically signed evidence bundle."

**[Run: POST /api/v1/evidence/export — show signed bundle generation]**

> "This bundle contains the finding, the MPTE verification proof, the applied fix, and the compliance mapping — SOC2 CC6.1, PCI-DSS Req 6.2, HIPAA 164.312. All automatic.
>
> The signature is hybrid RSA-SHA256 plus ML-DSA — that's FIPS 204, quantum-resistant. When quantum computing breaks RSA in 10 years, your evidence is still valid. 7-year WORM retention."

**[Run: POST /api/v1/evidence/export/verify — show signature verification]**

> "And auditors can verify with one API call. Machine-verifiable, tamper-proof. No more spreadsheets."

---

## ACT 5: PLATFORM — AI-Ready Infrastructure (45 seconds)

**[Screen: MCP gateway / tool discovery]**

> "One more thing. ALdeci is the first AppSec platform that AI agents can programmatically use."

**[Run: MCP tools/list — show 796 discovered tools]**

> "796 API endpoints, auto-discovered as MCP tools. Any AI agent — your internal copilot, a CI/CD bot, a security orchestrator — can discover ALdeci's capabilities and use them programmatically. stdio, SSE, and WebSocket transports. Forrester predicts 30% of enterprise vendors will launch MCP servers in 2026. We already ship one.
>
> And this entire platform deploys air-gapped. No internet required. Docker compose up. Under 1 gigabyte per year of storage."

---

## CLOSING (30 seconds)

**[Screen: Summary dashboard]**

> "In 5 minutes, you've seen the complete cycle:
>
> **Discover** — 25+ scanner formats ingested, 97% noise eliminated
> **Validate** — 19-phase micro-pentest proves exploitability
> **Remediate** — 10 fix types, confidence-based auto-apply
> **Comply** — quantum-secure evidence for auditors
> **Platform** — 796 MCP tools for AI agents, air-gapped deployment
>
> ALdeci turns 10,000 security findings into 10 actionable decisions — verified, not guessed — and fixes them before your next standup.
>
> Questions?"

---

## OBJECTION HANDLES (Keep Ready)

| Objection | Response |
|-----------|---------|
| "This looks like a lot of scanning — we already have scanners" | "ALdeci isn't another scanner. It's the brain above your scanners. We ingest Snyk, Wiz, Semgrep, Claude output — all of them. Day 1 value, zero rip-and-replace." |
| "How is multi-AI consensus better than one really good model?" | "Claude Code Security found 500+ zero-days with one model — brilliant. But single-model approaches have blind spots. Our 3+ model consensus catches what any individual model misses. When they disagree, that's the signal." |
| "Can we deploy this on-prem / air-gapped?" | "Yes. 8 native scanners, self-hosted AI via vLLM, quantum crypto — all work with zero internet. Under 1 GB/year storage. Docker compose up." |
| "What about the learning curve?" | "Upload a scanner report. That's step one. Auto-detection handles format mapping. Your existing tools, your existing workflow — ALdeci sits on top." |
| "How does this compare to Wiz?" | "Wiz is being acquired by Google this month. Your cloud security platform will be owned by a cloud vendor. ALdeci is Switzerland — works with everything, locked to no one." |

---

## TECHNICAL SETUP (Pre-Demo Checklist)

```bash
# Start the server
python -m uvicorn apps.api.app:create_app --factory --port 8000

# Verify all endpoints are healthy
bash scripts/demo-healthcheck.sh  # 34/34 should pass

# Seed demo data (Knowledge Graph)
curl -X POST http://localhost:8000/api/v1/knowledge-graph/seed-demo

# Verify key endpoints
curl http://localhost:8000/api/v1/brain/stats
curl http://localhost:8000/api/v1/mpte/stats
curl http://localhost:8000/api/v1/autofix/health
curl http://localhost:8000/api/v1/mcp/tools | python3 -c "import sys,json; print(len(json.load(sys.stdin)))"
```

---

*Script verified against live API endpoints from coordination-notes.md. All demo commands tested on 2026-03-02.*
