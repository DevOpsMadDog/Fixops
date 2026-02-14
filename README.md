[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/DevOpsMadDog/Fixops)

# ALdeci

**Enterprise DevSecOps Decision, Verification & Vulnerability Operations Platform**

*ALdeci turns noisy security outputs into provable release decisions, verified remediation, and AI-powered penetration testing.*

ALdeci is a comprehensive DevSecOps platform that operationalizes vulnerability management end-to-end. It ingests security artifacts (SBOM, SARIF, CVE, VEX, CNAPP), correlates and deduplicates findings into an application-centric **Knowledge Graph**, produces release-gate verdicts via multi-LLM consensus and policy evaluation, verifies exploitability through a world-class **Micro-Pentest Engine**, and generates cryptographically signed evidence for audit and compliance.

| Capability | Description |
|------------|-------------|
| **Ingest & Normalize** | SBOM/SARIF/CVE/VEX/CNAPP ingestion with business context enrichment |
| **Correlate & Deduplicate** | Knowledge Graph modeling, 5 correlation strategies, intelligent finding clustering |
| **Decide with Transparency** | Multi-LLM consensus (GPT-4, Claude, Gemini), policy engine, MITRE ATT&CK mapping |
| **Verify Exploitability** | AI-powered Micro-Pentest Engine — 19-phase scan, 4-state verdict system, multi-stage verification |
| **Operationalize Remediation** | Lifecycle tracking, SLA enforcement, bulk operations, team collaboration |
| **Prove & Retain** | RSA-SHA256 signed evidence, SLSA v1 provenance, configurable multi-year retention |
| **Automate & Extend** | YAML playbooks, compliance marketplace, Jira/Slack/GitHub/ServiceNow integrations |

**Interfaces:** 600+ REST API routes, 112+ CLI commands, 56 UI screens — deployable on-prem, air-gapped, or cloud.

---

## Quick Start

```bash
# 1. Clone and set up
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp .env.example .env
# Edit .env: set FIXOPS_API_TOKEN, OPENAI_API_KEY (optional)

# 3. Start backend (all 6 suites on port 8000)
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000

# 4. Start frontend
cd suite-ui/aldeci && npm install && npm run dev
# Open http://localhost:3001
```

---

## Repository Structure

```
ALdeci/
├── README.md                 # This file
├── Makefile                  # Build automation
├── pyproject.toml            # Python + pytest + tooling config (single file)
├── requirements.txt          # Python dependencies
├── sitecustomize.py          # Auto sys.path config for suite imports (Python magic)
├── usercustomize.py          # Runtime shims for test compatibility (Python magic)
│
├── suite-api/                # API Gateway — FastAPI app, routers, auth (port 8000)
├── suite-core/               # Core Engine — brain, pipeline, decision, CLI, agents
├── suite-attack/             # Attack Suite — micro-pentest engine, MPTE, simulations
├── suite-feeds/              # Threat Intel — NVD, CISA KEV, EPSS, ExploitDB, OSV, GitHub
├── suite-evidence-risk/      # Evidence & Risk — compliance, evidence bundles, risk scoring
├── suite-integrations/       # Integrations — Jira, Slack, GitHub, ServiceNow, SBOM
├── suite-ui/                 # Frontend — React + Vite + TypeScript (56 screens)
│
├── tests/                    # Test suites (unit, e2e, load, fixtures)
├── scripts/                  # Utility scripts (seed, deploy, monitor)
├── docs/                     # Documentation
├── data/                     # Runtime data (SQLite DBs, feeds, evidence)
├── docker/                   # Dockerfiles + docker-compose configs + Kubernetes
├── archive/                  # Legacy code archive
└── archive_not_needed/       # Temporary/test files moved during cleanup
```

**14 directories, 6 root files** — `sitecustomize.py` and `usercustomize.py` are Python auto-loaded magic files that must live at project root.

---

## Architecture

ALdeci runs as a **6-suite monolith** on a single port (8000) with modular separation:

```
┌─────────────────────────────────────────────────────────────────┐
│                        ALdeci Platform                          │
├───────────┬───────────┬───────────┬───────────┬────────────────┤
│ suite-api │suite-core │suite-attack│suite-feeds│suite-evidence  │
│  Gateway  │  Engine   │  Pentest  │ Threat    │  -risk         │
│  FastAPI  │  Brain    │  MPTE     │ Intel     │  Evidence      │
│  Auth     │  Pipeline │  Scanner  │ NVD/KEV   │  Compliance    │
│  Routers  │  Decisions│  AI Orch  │ EPSS/OSV  │  Risk Scoring  │
├───────────┴───────────┴───────────┴───────────┴────────────────┤
│                    suite-integrations                           │
│     Jira · Slack · GitHub · ServiceNow · SBOM · Backstage      │
├────────────────────────────────────────────────────────────────┤
│                       suite-ui (ALdeci)                        │
│         React + Vite + TypeScript · 56 screens · shadcn/ui     │
└────────────────────────────────────────────────────────────────┘
```

### Micro-Pentest Engine (MPTE)

The crown jewel — an AI-powered penetration testing engine:

- **19-phase vulnerability scan** — Security headers, SSL/TLS, SQLi, XSS, SSTI, CORS, Host Header Injection, HTTP Smuggling, Cache Poisoning, and more
- **4-state verdict system** — `VULNERABLE_VERIFIED`, `NOT_VULNERABLE_VERIFIED`, `NOT_APPLICABLE`, `UNVERIFIED`
- **Multi-stage verification** — Product Detection → Version Fingerprinting → Exploit Verification → Differential Confirmation
- **Multi-AI orchestration** — GPT-4 (Team Lead), Claude (Developer), Gemini (Architect) with consensus-based decisions
- **3-metric scoring** — Applicability, Test Coverage, Confidence per CVE
- **HTML report generation** — Professional pentest reports with PoC commands, MITRE ATT&CK mapping, architecture intelligence

### Multi-LLM Consensus Engine

Three AI providers with weighted voting and fallback:

| Role | Provider | Weight | Responsibility |
|------|----------|--------|----------------|
| Architect | Gemini | 0.35 | Attack surface analysis, business impact |
| Developer | Claude | 0.40 | Exploitability analysis, payload design |
| Team Lead | GPT-4 | 0.25 | Strategy, risk assessment, success criteria |

85% consensus threshold with graceful degradation to deterministic responses.

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Backend** | Python 3.14, FastAPI, uvicorn, SQLite (WAL mode) |
| **Frontend** | React 18, TypeScript, Vite, Tailwind CSS, shadcn/ui, framer-motion |
| **AI/ML** | OpenAI GPT-4, Anthropic Claude, Google Gemini, scikit-learn, pgmpy |
| **Threat Intel** | NVD 2.0 API, CISA KEV, FIRST.org EPSS, ExploitDB, OSV, GitHub Advisories |
| **Integrations** | Jira, Slack, GitHub, ServiceNow, GitLab, Azure DevOps |
| **Infrastructure** | Docker, docker-compose, Kubernetes |

---

## API & CLI

**600+ REST API routes** across 32 router modules. **112+ CLI commands** across 31 command groups.

Key routers: Ingestion, Pipeline, Enhanced Decision, Analytics, Audit, Reports, MPTE, Micro-Pentest, Feeds, Evidence, Deduplication, Remediation, Collaboration, Webhooks, Bulk Operations, Marketplace.

```bash
# Health check
curl http://localhost:8000/api/v1/health

# Run micropentest
curl -X POST -H "X-API-Key: $API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target_urls":["https://example.com"],"cve_ids":["CVE-2021-44228"]}' \
  http://localhost:8000/api/v1/micro-pentest/run

# Upload SBOM
curl -H "X-API-Key: $API_TOKEN" \
  -F "file=@sbom.json" http://localhost:8000/api/v1/inputs/sbom

# Run pipeline
curl -H "X-API-Key: $API_TOKEN" http://localhost:8000/api/v1/pipeline/run
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `FIXOPS_API_TOKEN` | Yes | — | API authentication token |
| `FIXOPS_MODE` | No | `enterprise` | Operating mode (`demo` / `enterprise`) |
| `OPENAI_API_KEY` | No | — | OpenAI GPT-4 API key |
| `ANTHROPIC_API_KEY` | No | — | Anthropic Claude API key |
| `GOOGLE_API_KEY` | No | — | Google Gemini API key |
| `FIXOPS_JIRA_TOKEN` | No | — | Jira integration token |
| `FIXOPS_SLACK_WEBHOOK` | No | — | Slack webhook URL |
| `FIXOPS_EVIDENCE_KEY` | No | — | Evidence encryption key (Fernet) |

LLM keys are optional — the platform falls back to deterministic responses when providers are unavailable.

---

## Docker Deployment

All Docker configs are in `docker/`:

```bash
# Standard
docker compose -f docker/docker-compose.yml up -d

# Enterprise (with ChromaDB)
docker compose -f docker/docker-compose.enterprise.yml up -d

# With PentAGI integration
make up-pentagi

# Verify
curl http://localhost:8000/api/v1/health
```

| Make Target | Description |
|-------------|-------------|
| `make up-pentagi` | Start ALdeci + PentAGI |
| `make up-pentagi-enterprise` | Enterprise + PentAGI |
| `make up-pentagi-demo` | Demo + PentAGI |
| `make down-pentagi` | Stop all services |
| `make demo` | Run demo pipeline |
| `make test` | Run test suite |
| `make clean` | Remove cached artifacts |

---

## Enterprise Integrations

| Integration | Status |
|-------------|--------|
| **Jira** | Production — full CRUD |
| **ServiceNow** | Production — full CRUD |
| **GitHub** | Production — full CRUD |
| **GitLab** | Production — full CRUD |
| **Azure DevOps** | Production — full CRUD |
| **Slack** | Ready — webhook notifications |
| **Confluence** | Outbound — create pages |

---

## Documentation

| Document | Description |
|----------|-------------|
| [Product Status](docs/FIXOPS_PRODUCT_STATUS.md) | Capability maps, workflow diagrams, code references |
| [API/CLI Reference](docs/API_CLI_REFERENCE.md) | Complete API-to-CLI mapping |
| [MPTE Integration](docs/MPTE_INTEGRATION.md) | Micro-pentest deployment guide |
| [Docker Guide](docs/DOCKER.md) | Docker and docker-compose documentation |
| [DeepWiki](https://deepwiki.com/DevOpsMadDog/Fixops) | AI-indexed documentation with search |

---

## License

Proprietary — See LICENSE file for details.

---

## Support

- [Documentation](docs/API_CLI_REFERENCE.md)
- [DeepWiki](https://deepwiki.com/DevOpsMadDog/Fixops)
- [Issues](https://github.com/DevOpsMadDog/Fixops/issues)
