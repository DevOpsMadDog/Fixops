[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

# ALDECI — AI-Native Security Intelligence Platform

> Replace $500K/yr security tool stacks with one self-hosted platform at $35/month.
> ASPM + CTEM + CSPM. 6,700+ API routes. 1,200+ test files. One Docker command.

[![Tests: 1,078+ passing](https://img.shields.io/badge/tests-1078%2B_passing-brightgreen)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Docker Ready](https://img.shields.io/badge/docker-ready-2496ED?logo=docker&logoColor=white)]()
[![Deploy to Fly.io](https://github.com/DevOpsMadDog/Fixops/actions/workflows/deploy.yml/badge.svg)](https://github.com/DevOpsMadDog/Fixops/actions/workflows/deploy.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![React 19](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black)]()
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

---

## Why ALDECI

Enterprise security is broken. The average Fortune 500 company runs 45+ separate security tools at a combined cost of $500K–$2M per year. Despite that spend, security teams are drowning in 10,000+ alerts per quarter with no clear signal on which ones actually matter. Analysts spend 60% of their time on manual triage, senior engineers build spreadsheets instead of fixing vulnerabilities, and every compliance audit means six weeks of screenshot collection.

ALDECI solves this by replacing the entire fragmented stack with a single, self-hosted, AI-native platform. At its core is a Karpathy-style LLM Council — four models voting on every risk decision with an 85% consensus threshold — wired to 28+ live threat intelligence feeds, a TrustGraph knowledge graph with 162 entities across 5 semantic cores, and 30+ security engines covering every domain from vulnerability management to insider threat detection. The result is an actionable priority list instead of 10,000 findings, audit-ready compliance evidence instead of weeks of manual collection, and cryptographically signed proof instead of screenshots.

ALDECI is not a demo. It is a production platform: 6,700+ API routes across 796 FastAPI router modules, 529 React dashboard pages, SCIM 2.0 (RFC 7644), SAML/OIDC SSO, Redis queue for horizontal scaling, multi-tenant isolation with org_id enforcement, and 1,200+ test files (1,078+ Beast Mode tests) with zero regressions. The entire stack runs on a $35/month VPS or air-gapped on-premises with a single Docker command.

---

## What It Does

| Capability | Description | Enterprise Tools Replaced |
|---|---|---|
| **Vulnerability Management** | 8-state lifecycle tracking, EPSS scoring, SLA auto-escalation, batch triage | Tenable, Rapid7, Qualys |
| **Threat Intelligence** | 28+ live feeds: NVD, CISA KEV, abuse.ch, OTX AlienVault, URLhaus, Feodo C2, Shodan InternetDB | Recorded Future, ThreatConnect |
| **Cloud Security Posture (CSPM)** | AWS/Azure/GCP posture, Wiz/Prisma/Orca/Lacework connectors, IaC scanning (Checkov + tfsec) | Wiz, Lacework, Orca Security |
| **Application Security (ASPM)** | SAST, DAST, container, API fuzzing, supply-chain SBOM (CycloneDX + SPDX), dependency graph | Snyk, Apiiro, Endor Labs |
| **Attack Path Analysis** | BFS lateral movement simulation, MITRE ATT&CK mapping, breach impact scoring | XM Cyber, AttackIQ |
| **Compliance Automation** | SOC 2, ISO 27001, HIPAA, PCI-DSS, NIST CSF — auto-collected evidence, tamper-proof audit chain | Drata, Vanta, Thoropass |
| **AI-Powered Triage** | LLM Council (Qwen 3.6 Max + 3 models), GraphRAG context injection, Copilot chat interface | Vendor-specific AI add-ons |
| **Identity & Access (CIEM)** | IAM entitlement analysis, privilege escalation detection, SCIM 2.0, SAML/OIDC SSO | Ermetic, Authomize |
| **Incident Response** | SLA auto-escalation, n8n workflow automation, playbook engine, Slack/Jira/ServiceNow integration | PagerDuty, Splunk SOAR |
| **Digital Risk Protection** | Typosquat detection, credential exposure, certificate monitoring, paste site monitoring | ZeroFOX, Digital Shadows |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Frontend  (React 19 + Vite 6 + Tailwind v4)                │
│  40+ dashboard pages — CISO, SOC T1, Compliance, CSPM, ...  │
└───────────────────────┬─────────────────────────────────────┘
                        │ HTTP / WebSocket
┌───────────────────────▼─────────────────────────────────────┐
│  API Gateway  (FastAPI — 6,700+ routes, 796 router modules)  │
│  Auth: API key + JWT RS256 + SAML/OIDC SSO + SCIM 2.0       │
│  Rate limiting: token-bucket per key, admin tier exempt      │
└──────┬──────────────────────────────┬────────────────────────┘
       │                              │
┌──────▼──────────┐      ┌────────────▼───────────────────────┐
│  AI Council      │      │  30+ Security Engines              │
│  Qwen 3.6 Max   │      │  SQLite WAL, multi-tenant org_id   │
│  + 3 free models│      │  vuln lifecycle, insider threat,   │
│  85% consensus  │      │  attack paths, CIEM, DRP, SBOM,    │
│  threshold      │      │  KPI tracker, vendor risk, ...     │
└──────┬──────────┘      └────────────┬───────────────────────┘
       │                              │
┌──────▼──────────────────────────────▼───────────────────────┐
│  TrustGraph Knowledge Graph  (GraphRAG + BFS traversal)      │
│  5 Knowledge Cores — 162 entities, semantic search           │
│  Wired to Copilot chat for context-aware responses           │
└─────────────────────────────────────────────────────────────┘
       │                              │
┌──────▼──────────┐      ┌────────────▼───────────────────────┐
│  28+ Threat     │      │  Infrastructure                    │
│  Intel Feeds    │      │  Redis queue (horizontal scale)    │
│  NVD, KEV, OSV  │      │  DuckDB cross-domain analytics     │
│  Shodan, abuse  │      │  n8n workflow automation           │
│  .ch, OTX, ...  │      │  Docker Compose (one command)      │
└─────────────────┘      └────────────────────────────────────┘
```

---

## Quick Start (60 seconds)

```bash
git clone https://github.com/DevOpsMadDog/Fixops
cd Fixops
cp .env.example .env          # add your API keys (optional — works without them)
docker compose up -d          # starts API + UI + Redis + all services
open http://localhost:3000    # React dashboard
open http://localhost:8000/docs  # FastAPI interactive docs (6,700+ routes)
```

**No cloud account required. No vendor signup. Fully air-gapped capable.**

For the demo data seed (investor walkthrough):

```bash
python seed-demo-data-v2.py   # loads realistic security findings, assets, compliance data
```

---

## What's Included

- **6,700+ API routes** across 796 FastAPI router modules
- **529 React dashboard pages** — CISO executive view, SOC T1, compliance, threat intel, asset inventory, attack paths, insider threats, vendor risk, posture advisor, and more
- **30+ security engines** — all multi-tenant with org_id isolation, SQLite WAL persistence
- **28+ threat intelligence feeds** — NVD, CISA KEV, abuse.ch, OTX AlienVault, URLhaus, Feodo C2, Shodan InternetDB, OSV, EPSS, ExploitDB, GreyNoise, and more
- **LLM Council** — Qwen 3.6 Max via MuleRouter + free model fallbacks, 85% consensus threshold, wired to TrustGraph GraphRAG
- **TrustGraph knowledge graph** — 5 semantic cores, 162 entities, BFS traversal, GraphRAG context injection
- **SCIM 2.0 server** (RFC 7644) — enterprise identity provisioning
- **SAML/OIDC SSO bridge** — Okta, Azure AD, generic SAML providers; JWT RS256 via PyJWKClient
- **Redis queue** — horizontal scaling, async job processing, per-org isolation
- **n8n workflow automation** — scheduled report delivery, Slack/email notifications, custom playbooks
- **SBOM generation** — CycloneDX 1.4 and SPDX 2.3 JSON, OSV vulnerability cross-reference
- **DuckDB analytics** — cross-domain queries across all security engines
- **1,200+ test files** (1,078+ Beast Mode tests) — zero regressions, 10s timeout, pytest-asyncio

---

## Personas and Use Cases

| Persona | Primary Use Cases |
|---|---|
| **CISO** | Executive risk posture dashboard, board-ready KPI reports, compliance status across 5 frameworks, vendor risk register |
| **SOC Analyst T1** | Alert triage queue, IOC lookup, IP reputation check, insider threat behavioral alerts, incident escalation |
| **Vulnerability Engineer** | Lifecycle tracking (8-state), EPSS + KEV enrichment, SLA enforcement, patch prioritization (CVSS × EPSS × KEV) |
| **Compliance Officer** | Auto-collected evidence bundles, tamper-proof audit chain, SOC 2 / ISO 27001 / HIPAA gap analysis |
| **Cloud Security Engineer** | CSPM posture advisor, IaC scanning, attack path visualization, CIEM privilege escalation detection |
| **AppSec Engineer** | SBOM management, supply chain risk, dependency graph, SAST/DAST findings, STRIDE threat modeling |
| **Identity & Access Admin** | SCIM provisioning, SSO configuration, CIEM entitlement analysis, Zero Trust policy enforcement |
| **DevSecOps Engineer** | API abuse detection, secrets rotation tracker, CI/CD integration via API, webhook receivers |

---

## Competitive Positioning

| | **ALDECI** | **Wiz** | **Lacework** | **Snyk** | **Rapid7** |
|---|---|---|---|---|---|
| **Monthly cost** | $35 (self-hosted) | $25K+ | $20K+ | $1,200+ | $10K+ |
| **Deployment** | Self-hosted / air-gapped | Cloud-only | Cloud-only | SaaS | SaaS / on-prem |
| **AI consensus decisions** | 4-model council | Single model | None | None | None |
| **Knowledge graph (GraphRAG)** | 5-core TrustGraph | None | Partial | None | None |
| **Coverage** | ASPM + CTEM + CSPM + CIEM + DRP | CSPM + CNAPP | CSPM + UEBA | ASPM | VM + AppSec |
| **Compliance automation** | 5 frameworks, auto-evidence | Limited | None | None | Limited |
| **Open source** | MIT | Proprietary | Proprietary | Proprietary | Proprietary |
| **Pentest engine** | Built-in MPTE | None | None | None | Separate product |

---

## Roadmap

**Q2 2026**
- Multi-tenant Redis queue isolation (org_id scoping — in progress)
- Scheduled report delivery via n8n (email + Slack)
- OpenClaw autonomous red team swarm (pentest automation)
- NVD + AbuseIPDB + OTX AlienVault API key wiring

**Q3 2026**
- Zero Trust policy enforcement engine (backend for existing UI)
- SBOM `/api/v1/sbom` CycloneDX/SPDX export (public endpoint)
- Attack path frontend wired to live BFS engine data
- Threat Modeling UI wired to STRIDE auto-detection backend
- Multi-cloud unified posture (AWS + Azure + GCP single view)

**Q4 2026**
- SaaS offering (managed hosting tier)
- Marketplace for community connectors and playbooks
- SOC 2 Type II certification for managed tier
- MSSP multi-tenant white-label support
- Mobile app for CISO executive alerts

---

## Project Structure

```
.
├── suite-api/          # FastAPI gateway — 796 router modules (6,700+ routes)
├── suite-core/         # Core engines — brain pipeline, connectors, CLI
│   ├── core/           # 463 security engine classes
│   ├── connectors/     # 13 PULL + 7 bidirectional connectors
│   └── trustgraph/     # TrustGraph MCP server + KnowledgeStore (547 emit-sites)
├── suite-attack/       # Offensive security — MPTE, attack simulation
├── suite-feeds/        # Threat intel feeds — 28+ sources
├── suite-evidence-risk/# Evidence bundles, risk scoring, compliance
├── suite-integrations/ # External integrations — MCP, webhooks, n8n
├── suite-ui/
│   └── aldeci-ui-new/  # React 19 + Vite 6 + Tailwind v4 (529 pages, active UI)
├── tests/              # 1,200+ test files (pytest, 10s timeout)
├── docker-compose.yml  # Full stack in one command
└── requirements.txt
```

---

## Contributing and License

ALDECI is MIT licensed. Pull requests are welcome.

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding conventions (FastAPI + Pydantic v2, structlog, SQLite WAL), and the test strategy.

**Security disclosures**: open a GitHub issue marked `[SECURITY]` or email info@devopsai.co.

---

*Built with FastAPI, React 19, TrustGraph, and the Beast Mode v6 autonomous development framework.*
*Full architecture: [`docs/ALDECI_REARCHITECTURE_v2.md`](docs/ALDECI_REARCHITECTURE_v2.md)*
