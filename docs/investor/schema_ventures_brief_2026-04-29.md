# Aldeci — 1-Page Brief for Schema Ventures

**Date:** 2026-04-29
**Founder contact:** [redacted]
**Investor:** Aarthi Ramamurthy, Schema Ventures (Fund 1, 21 investments)

**Schema thesis match:** "Developer tools & infrastructure → AI powered pentesting" (verbatim from Aarthi's 2026-04-28 LinkedIn post).

---

## What we're building

**Aldeci is an AI-native security operating system** that unifies ASPM + CSPM + CTEM in one self-hostable platform. AI pen-testing is one of 12 verified primitives, not the product.

The Brain Pipeline runs every finding through 12 steps: connect → normalize → resolve identity → false-positive auto-suppress → deduplicate → build knowledge graph → enrich threats → score risk → apply policy → multi-LLM consensus → micro-pen-test → run playbooks → generate evidence.

---

## Why we're not just-another-AI-pentester (vs PentAGI / Nebula / Garak / BurpGPT / Vulnhuntr)

| Them | Us |
|------|-----|
| Single-LLM wrapper (mostly GPT-4) | 4-member multi-LLM Karpathy 3-stage council with verified consensus on free-tier (Mulerouter + OpenRouter + Ollama + vLLM, $0/month) |
| CLI tool or Burp plugin | Full platform: 6300+ API endpoints, 5 sub-apps (ASPM/CSPM/CTEM/GRC/Platform), 30 personas |
| Output: text report | Output: feeds into TrustGraph (475 wired engines), DPO closed-loop learning (5,196 pairs), unified risk score across 17 threat feeds |
| Use case: dev runs against own app | Use case: enterprise platform replacing Snyk + Wiz + Apiiro at 1/30th the price |
| No federal / SCIF | Full SCIF / air-gap / FIPS / cosign DSSE signing — none of Snyk/Wiz/Apiiro/Aikido ship this either |

---

## Defensible product moats

1. **MPTE exploit-verification** — 1,098 LOC engine, 17 ScanPhase enum, real Yahoo Host-header-injection report (see `data/pentest_report_data.json`)
2. **Multi-LLM Council** — verified working today on free-tier providers (commit `1aaecf27`)
3. **17-feed catalog + correlator** — CISA KEV + NVD + EPSS + GHSA + OSV + ExploitDB + OTX + AbuseIPDB + Tor + Spamhaus + Nuclei + MalwareBazaar + URLhaus + PhishTank + SANS ISC + URLscan + GreyNoise + Censys + SecurityTrails + HIBP + MITRE ATT&CK + SigmaHQ + DBIR + CIS Benchmark + meta registry
4. **Federal SCIF / air-gap / on-prem** — Iron Bank Dockerfile + SoftHSM PKCS#11 + FIPS 140-2 boundary + ed25519 air-gap signing + all-on-prem LLM. **Snyk/Wiz/Apiiro/Aikido are all SaaS-only.**
5. **Self-hosted full platform** — same.
6. **Brain Pipeline 12-step** — 4,524 LOC of real step implementations.
7. **Unified ASPM+CSPM+CTEM** — customers buy 3 vendors today; we replace with 1.

---

## Traction / validation

- **6,300+** API endpoints registered
- **753** Beast Mode tests passing throughout dispatch (zero regressions)
- **475** TrustGraph-wired production engines (68.8% of in-scope code)
- **30** native personas with workflow tests (waves 1-4 shipped)
- **5,196** DPO training pairs from real council disagreements
- **17** native threat-intel feeds with cross-feed correlator engine
- **121,878-node** knowledge graph (graphify) with 1,706 communities
- **Public self-scan dashboard** at `https://devopsmaddog.github.io/Fixops/self-scan/` — Aldeci runs Aldeci on Aldeci's code, results published. We are our own first reference customer.
- **Yahoo Host-header-injection report** as concrete pen-test evidence

---

## Pricing differentiation

| Tier | Price | Snyk equivalent | Wiz equivalent |
|------|-------|----------------|----------------|
| Starter | $199/mo ($2.4K/yr) | N/A (Snyk starts at $25K/yr) | N/A |
| Pro | $499/mo ($6K/yr) | $50K-150K/yr | $80K/yr |
| Enterprise | $1,499/mo ($18K/yr) | $150K-500K/yr | $300K-1M+/yr |
| Federal SCIF pilot | $50-250K ACV | Not offered | Not offered |

---

## Round

- **Stage:** Pre-seed / Seed
- **Use of funds:** Sales motion + 1 reference customer onboarding + UX polish (last 117 pages → 30-screen target) + community building around the OSS feed catalog
- **Why now:** Snyk/Wiz/Apiiro/Aikido all locked into SaaS-only. Federal mandate for on-prem + air-gap creates an underserved $2B+ subsegment we own structurally.

---

## Asks

1. **15-min call** to walk the Yahoo demo + multi-LLM council convening live
2. **Intro to one mid-market security buyer** (200-2000 employees, regulated vertical) for design partnership
3. **Schema portfolio synergies** — agent authentication / observability companies in your portfolio could be natural integrations

---

*Repo: github.com/DevOpsMadDog/Fixops · Live demo: 5-min Loom on request · Founder: [redacted]*
