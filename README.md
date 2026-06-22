[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

# ALDECI — AI-Native Security Intelligence Platform

> **Ingest the scanner output you already have. Get a real, AI-reasoned priority list — not 10,000 more alerts.**
> A single self-hosted ASPM + CTEM + CSPM platform that replaces a fragmented six-figure tool stack. Runs on a VPS or fully air-gapped with one Docker command.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)]()
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)]()

---

## The problem

Enterprises run 45+ security tools costing $500K–$2M/year and still drown in tens of thousands of findings per quarter with no clear signal on what matters. Analysts burn the majority of their time on manual triage; every audit means weeks of screenshot collection.

## What ALDECI does differently

ALDECI is **ingest-first**. You point it at the scanner output you already produce — SARIF, Trivy, Prowler, Snyk, Checkov, SBOMs, and 60+ other formats — and it does the reasoning your stack doesn't:

- **A real multi-LLM council** reasons over each finding (via OpenRouter) and returns a verdict with a real cost and distinct member reasoning. If no model is configured, it says so — it **never fabricates a verdict**.
- **A TrustGraph knowledge graph** correlates findings across assets (blast radius, related CVEs, lateral paths) and enriches every council decision.
- **A 12-step Brain Pipeline + MPTE exploitability** turns raw findings into a deduped, correlated, prioritized exposure list.

The hard rule everywhere: **no mocks, no fabricated scores.** An un-ingested tenant sees honest zeros and a branded empty state — never a fake "all clear." This is enforced by blocking CI gates, not good intentions.

---

## What it replaces

| Capability | What it does | Tools it displaces |
|---|---|---|
| **Vulnerability mgmt** | 8-state lifecycle, EPSS/KEV enrichment, SLA escalation, batch triage | Tenable, Rapid7, Qualys |
| **ASPM** | Ingests SAST/DAST/container/SBOM (CycloneDX + SPDX), reachability (Python/TS/Java) | Snyk, Apiiro, Endor |
| **CSPM** | Cloud posture from ingested findings; Prowler/Checkov; AWS/Azure/GCP | Wiz, Lacework, Orca |
| **CTEM** | Attack-path BFS, MITRE ATT&CK mapping, exposure funnel (real noise reduction) | XM Cyber |
| **Threat intel** | 28+ feeds (NVD, CISA KEV, abuse.ch, OTX, URLhaus, OSV, EPSS); honest-empty until refreshed | Recorded Future |
| **Compliance evidence** | Auto-collected, tamper-evident, chain-of-custody bundles for *your* ATO / framework audits | Drata, Vanta |
| **AI triage** | Multi-LLM council + TrustGraph GraphRAG context; honest-or-unconfigured | vendor AI add-ons |
| **CIEM / identity** | Entitlement analysis, privilege-escalation detection, SCIM 2.0, SAML/OIDC SSO | Ermetic, Authomize |
| **MPTE pentest** | Built-in exploitability verification (real Nuclei connector, or honest 503) | separate products |

---

## The moat (what's genuinely hard to copy)

1. **Multi-LLM council** — independent models reason per finding; real cost, real reasoning, never a placebo verdict.
2. **TrustGraph correlation** — graph-enriched verdicts (blast radius, correlated CVEs, related findings).
3. **12-step Brain Pipeline** — ingest → dedup → correlate → prioritize → exposure, all from real data.
4. **MPTE** — exploitability verification instead of raw CVSS.
5. **Honest-empty / NO-MOCKS** — the product tells the truth when it has no data; provably, via CI.

---

## Architecture

```
 React 19 UI (299 pages)  ──HTTP/WS──►  FastAPI gateway (~8,300 routes / 813 routers)
                                         auth: API-key + JWT + SAML/OIDC + SCIM 2.0
                                         org_id resolved from auth context (tenant-isolated)
        ┌──────────────────────────────────────┴───────────────────────────┐
        ▼                                                                    ▼
  Multi-LLM Council (OpenRouter)        464 security engines (SQLite WAL, org-scoped)
  real-or-honestly-unconfigured          vuln · cloud · attack-path · CIEM · DRP · SBOM …
        │                                                                    │
        └───────────────►  TrustGraph knowledge graph (GraphRAG + BFS)  ◄────┘
                                          │
                Ingest-first: 60+ scanner normalizers · 28+ threat-intel feeds
                Infra: Redis queue · DuckDB analytics · Docker Compose (one command)
```

---

## Quick start (one command)

```bash
git clone https://github.com/DevOpsMadDog/Fixops && cd Fixops
cp .env.example .env          # optional keys (OpenRouter for the council, feeds, SSO)
docker compose up -d          # API + UI + Redis + services
open http://localhost:3000    # React dashboard
open http://localhost:8000/docs  # interactive API docs
```

**No cloud account. No vendor signup. Air-gap capable.** Then ingest real scanner output:

```bash
curl -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $FIXOPS_API_TOKEN" -H "X-Org-ID: my-org" \
  -F file=@scan.sarif -F scanner_type=sarif -F app_id=my-app
# → real findings, deduped, org-scoped. Read them back:
curl "http://localhost:8000/api/v1/security-findings/?org_id=my-org" -H "X-API-Key: $FIXOPS_API_TOKEN"
```

---

## Engineering facts (measured, not marketing)

- **~8,300 API routes** across **813** FastAPI router modules · **464** security engines
- **299** React 19 pages (Vite 6 + Tailwind v4)
- **1,468 test files** (~45K tests). A 756-test "Beast" smoke is the fast wiring tripwire; **25 blocking CI gates** guard the real invariants
- **36 capability specs** (`specs/SPEC-*.md`) with acceptance criteria
- **Tenant isolation**: `org_id` is derived from the auth context (JWT/contextvar), never a spoofable client param — enforced across the API and **CI-gated** (SPEC-034)
- **Security posture**: fail-closed auth fallbacks (CI-gated), per-router API-key/JWT, rate limiting, air-gap egress guard
- Storage: SQLite WAL per domain + DuckDB analytics

> **Deployment & compliance reality**: ALDECI ships **on-prem / air-gapped**. It does not claim a vendor SaaS attestation — instead it *supplies the evidence* your auditors need for **your** ATO / SOC 2 / ISO 27001 / NIST 800-53 program (tamper-evident, chain-of-custody bundles).

---

## Quality gates (why you can trust the numbers)

Every PR to `main` must pass blocking gates in `.github/workflows/regression-gates.yml`, including:

- **NO-MOCKS** (UI fires real `/api/v1` calls; no fixtures) and **ingest-first honest-empty** (no fabricated scores)
- **Real-moat E2E** — a real scanner file ingests to real findings; the council is real-or-honestly-unconfigured (+ a nightly live gate asserting `cost_usd > 0`)
- **Customer-journey E2E** — upload → my org's findings → tenant-isolated → verdict → evidence
- **Tenancy** (`org_id` from auth context) and **fail-closed auth** source gates
- OWASP regression lockdown, engine/router import sweep, UI routing integrity, per-moat gates (TrustGraph, MPTE, CSPM, …)

---

## Project structure

```
.
├── suite-api/           # FastAPI gateway — 813 router modules (~8,300 routes)
├── suite-core/          # Core engines — Brain Pipeline, council, connectors, TrustGraph
│   ├── core/            # 464 security engine classes (org-scoped, SQLite WAL)
│   ├── connectors/      # PullConnector framework + 60+ scanner normalizers
│   └── trustgraph/      # TrustGraph store + GraphRAG
├── suite-attack/        # MPTE — exploitability verification, attack simulation
├── suite-feeds/         # 28+ threat-intel feed importers
├── suite-evidence-risk/ # Evidence bundles, risk scoring, compliance evidence
├── suite-integrations/  # MCP, webhooks, automation
├── suite-ui/aldeci-ui-new/  # React 19 + Vite 6 + Tailwind v4 (299 pages)
├── specs/               # 36 capability specs with acceptance criteria
├── tests/               # 1,468 test files
└── docker-compose.yml   # full stack, one command
```

---

## Contributing & license

MIT licensed — PRs welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, conventions (FastAPI + Pydantic v2, structlog, SQLite WAL), and the tiered test strategy.

**Security disclosures**: open a GitHub issue tagged `[SECURITY]` or email info@devopsai.co.
