# ALdeci / FixOps - Copilot Instructions

> **Mission**: ALdeci is a **CTEM+ Decision Intelligence platform** for application security.
> ALdeci is NOT just an aggregator — it is a full Continuous Threat Exposure Management (CTEM) platform
> with **8 built-in native scanners**, an **AI-powered AutoFix engine** (10 fix types), and a **12-step
> Brain Pipeline** that runs the complete CTEM lifecycle: Discover → Validate → Remediate → Comply.
>
> Every enterprise runs 5-15 security scanners that flood teams with 11,300+ uncontextualized findings.
> ALdeci ingests results from ALL of them AND runs its own native scans, deduplicates, correlates via
> a knowledge graph, verifies exploitability with micro-pentests, makes AI-powered decisions using
> multi-LLM consensus, auto-fixes code, generates quantum-secure compliance evidence — and learns
> from every outcome.
>
> **Air-gapped capable**: All 8 native scanners work with ZERO external dependencies.
> **Switzerland positioning**: Also works with every external tool, replaces none.
>
> **Canonical CTEM+ Reference**: `docs/CTEM_PLUS_IDENTITY.md`

## VISION REFERENCE — docs/VISION_TO_ACCOMPLISH.MD

**ALL work MUST serve at least one of the 10 Vision Pillars. If it doesn't, it doesn't belong.**

| # | Pillar | Promise |
|---|--------|---------|
| V1 | **APP_ID-Centric Architecture** | Every finding, decision, evidence traces to App → Component → Feature |
| V2 | **10-Phase Security Lifecycle** | Design → IDE → ALM → Pre-merge → Build → IaC → KG → AI → Remediation → Self-Learning |
| V3 | **Decision Intelligence** | "What to DO about a risk, not just what the risk IS" |
| V4 | **Multi-LLM Consensus / Self-Hosted AI** | 3+ LLMs with 85% threshold OR zero-token self-hosted model |
| V5 | **MPTE Verification** | Prove exploitability, don't just detect vulnerability |
| V6 | **Quantum-Secure Evidence** | FIPS 204 ML-DSA + RSA hybrid, 7-year WORM retention |
| V7 | **MCP-Native AI Platform** | First AppSec platform AI agents can programmatically use (650 auto-discovered tools) |
| V8 | **Self-Learning (5 Feedback Loops)** | Decision outcomes, MPTE results, FP rates, remediation success, policy violations |
| V9 | **Air-Gapped / On-Prem Deployment** | Full offline capability on commodity hardware (<1 GB/year storage) |
| V10 | **CTEM Full Loop with Cryptographic Proof** | Discover → Prioritize → Validate → Remediate → Measure (with signed evidence at each step) |

## CTEM+ Platform Identity (NOT Just an Aggregator)

ALdeci is a **full CTEM platform** with native scanning capabilities AND a neutral orchestration layer:

### 8 Native Scanners (ALL REAL, ALL Air-Gapped)

| Scanner | Engine File | LOC | Endpoints |
|---------|-------------|-----|----------|
| **SAST** | `suite-core/core/sast_engine.py` | 465 | 4 |
| **DAST** | `suite-core/core/dast_engine.py` | 533 | 2 |
| **Secrets** | `suite-core/core/secrets_scanner.py` | 775 | 7 |
| **Container** | `suite-core/core/container_scanner.py` | 410 | 3 |
| **CSPM/IaC** | `suite-core/core/cspm_engine.py` | 586 | 9 |
| **API Fuzzer** | `suite-attack/api/api_fuzzer_router.py` | ~200 | 3 |
| **Malware** | `suite-attack/api/malware_router.py` | ~200 | 4 |
| **LLM Monitor** | `suite-core/api/llm_monitor_router.py` | ~200 | 4 |

### AutoFix Engine (~1,515 LOC — `suite-core/core/autofix_engine.py`)
10 fix types: CODE_PATCH, DEPENDENCY_UPDATE, CONFIG_HARDENING, IAC_FIX, SECRET_ROTATION, PERMISSION_FIX, INPUT_VALIDATION, OUTPUT_ENCODING, WAF_RULE, CONTAINER_FIX.
Confidence: HIGH=auto-apply, MEDIUM=review, LOW=manual. 14 API endpoints.

### OSS/SCA Tools (`suite-integrations/api/oss_tools.py`, 206 LOC)
Trivy, Grype, Sigstore/Cosign, OPA integration. SBOM generation (CycloneDX 1.5/SPDX 2.3). 8 endpoints.

### Switzerland Positioning (Dual Mode)
ALdeci is the **neutral decision layer** above all security tools:
- Snyk, Semgrep, Trivy, Wiz, Prisma, ZAP, Checkmarx → ALdeci normalizes, deduplicates, decides → Jira, Slack, GitHub PRs
- **Day 1 value**: No rip-and-replace. Works with what enterprises already own
- **Air-gapped mode**: Native scanners provide full CTEM coverage when external tools unavailable

## 5 Workflow Spaces (Steve Jobs UI Redesign)

The UI is organized by **WHAT PEOPLE NEED TO DO**, not what the product can do:

| Space | Question it Answers | Key Pages |
|-------|-------------------|-----------|
| 🎯 **MISSION CONTROL** | "What needs attention now?" | Command Dashboard, Executive View, SLA Dashboard, Live Feed, Risk Overview |
| 🔍 **DISCOVER** | "What risks exist?" | Finding Explorer, Code Scanning, Secrets, IaC, Cloud, Containers, SBOM, Knowledge Graph, Attack Paths, Threat Feeds |
| ⚡ **VALIDATE** | "Is it actually exploitable?" | MPTE Console, Attack Simulation, FAIL Engine, Playbooks, Reachability |
| 🔧 **REMEDIATE** | "How do I fix it?" | Remediation Center, AutoFix, Bulk Operations, Collaboration, Workflows, Tickets |
| 🛡️ **COMPLY** | "Can I prove we're secure?" | Compliance Dashboard, Evidence Vault, Evidence Export, SOC2, SLSA, Audit Trail, Reports, Analytics |

### 25 Personas Served

Leadership (CISO, VP Eng, CTO, CFO), Security Ops (9 roles), Engineering (6 roles), Data/AI (4 roles), External (Auditor, Consultant).

## 9 Unique Differentiators (No Competitor Has These)

1. **8 Native Scanners + AutoFix** — Full CTEM pipeline built-in, works air-gapped (5,315+ LOC across 10 engines)
2. **12-Step Brain Pipeline** — CONNECT→NORMALIZE→RESOLVE→DEDUPLICATE→GRAPH→ENRICH→SCORE→POLICY→CONSENSUS→PENTEST→AUTOFIX→EVIDENCE
3. **FAIL Engine** — Chaos engineering for AppSec (fault injection + response grading)
4. **MCP Gateway** — 650 auto-discovered tools for AI agents (Copilot, Cursor, Claude Code)
5. **Single AI Agent** — $0/mo self-hosted via vLLM (replaces $6K/mo vendor APIs)
6. **Quantum-Secure Crypto** — FIPS 204 ML-DSA + RSA hybrid signatures
7. **Zero-Gravity Data** — 4-tier aging reduces on-prem storage 95% (<1 GB/yr)
8. **MPTE** — 19-phase deterministic scanner proving exploitability
9. **Switzerland + CTEM Dual Mode** — Works with every tool AND provides full native coverage when air-gapped

## AI Agent Swarm System (Claude Opus 4.6 Fast Mode)

**Model**: All agents run **Claude Opus 4.6 (fast mode)** via Claude Code CLI.
**Architecture**: 19 senior agents + 30 junior swarm workers, all using Claude Opus 4.6.

| Phase | Agents | Role |
|-------|--------|------|
| 0 | vision-agent, agent-doctor | Pre-flight vision check + health |
| 1 | context-engineer | Codebase map + daily briefing |
| 2 | ai-researcher, data-scientist, enterprise-architect | Research + architecture (parallel) |
| 2.5 | ux-architect | UI information architecture audit (before build) |
| 3 | backend-hardener, frontend-craftsman, threat-architect | Build + harden (parallel) |
| 3.5 | swarm-controller + 30 juniors | Parallel micro-tasks |
| 4 | security-analyst, qa-engineer | Validate + test (parallel) |
| 4.5 | persona-api-validator | Persona API flow validation |
| 5 | devops-engineer | Infrastructure |
| 6 | Debate round (3 rounds) | Cross-agent review |
| 7 | marketing-head, technical-writer, sales-engineer | Go-to-market (parallel) |
| 8 | scrum-master | Daily demo + coordination |
| 9 | agent-doctor | Post-run audit |
| 10 | vision-agent | Post-flight vision alignment |

**Shared Context Protocol (SCP)**: Every agent reads CEO_VISION.md, VISION_TO_ACCOMPLISH.MD, sprint-board.json, and context_log.md before work. Every agent appends outcomes to context_log.md after work.

**Agent Files**: `.claude/agents/*.md` — 19 agent definitions
**Orchestration**: `scripts/run-ai-team-unleashed.sh` — UNLEASHED mode (all agents, Claude Opus 4.6, unlimited budget)
**State**: `.claude/team-state/` — sprint board, agent statuses, debates, swarm outputs

## Architecture Overview

**7-Suite Monolith** running on port 8000. All suites share imports via `sitecustomize.py` (auto-loaded by Python).

| Suite | Purpose | Key Files |
|-------|---------|-----------|
| `suite-api` | FastAPI gateway, 61 routers, auth | `apps/api/app.py`, `*_router.py` |
| `suite-core` | Brain, pipeline, decisions, connectors, **native scanners**, **AutoFix engine** | `core/brain_pipeline.py` (1,663 LOC), `core/sast_engine.py`, `core/dast_engine.py`, `core/secrets_scanner.py`, `core/container_scanner.py`, `core/cspm_engine.py`, `core/autofix_engine.py` (~1,515 LOC), `core/connectors.py` |
| `suite-attack` | MPTE, attack sim, FAIL engine | `attack/micro_pentest.py`, `attack/mpte_advanced.py` |
| `suite-feeds` | Threat intel (NVD, KEV, EPSS, OSV, ExploitDB, GitHub) | `feeds/*.py` |
| `suite-evidence-risk` | Compliance, evidence bundles, risk scoring | `risk/*.py`, `evidence/*.py` |
| `suite-integrations` | Jira, Slack, GitHub, MCP connectors | (shares connectors from suite-core) |
| `suite-ui` | React frontends | `aldeci/` (ACTIVE — being wired to real APIs). NOTE: `aldeci-ui-new/` does NOT exist on disk. |

### Codebase Scale
- **~465 Python backend files** (~195K LOC) + **~99 TypeScript source files** (~42K LOC)
- **768 API endpoints** across 64 router files + 8 non-standard files in 6 backend suites
- **385 test files**, 13,674 tests collected (~183K test LOC)
- **17 production connectors** (7 integration in `core/connectors.py` + 10 security tool in `core/security_connectors.py`) + universal REST/MCP ingest (4,340 total LOC)

## Critical Patterns

### Import Resolution
- **sitecustomize.py** at project root auto-prepends all suite paths to `sys.path`
- Imports like `from core.connectors import JiraConnector` work from anywhere
- Never manually manipulate `sys.path`; `sitecustomize.py` handles it

### 12-Step Brain Pipeline (core/brain_pipeline.py)
Every finding flows: CONNECT → NORMALIZE → RESOLVE → DEDUPLICATE → BUILD GRAPH → ENRICH → SCORE → EVALUATE POLICY → MULTI-LLM CONSENSUS → MICRO-PENTEST → AUTOFIX → GENERATE EVIDENCE

### Connector Pattern (suite-core/core/connectors.py)
All external connectors inherit from `_BaseConnector` with:
- Circuit breaker (`CircuitBreaker` dataclass)
- Retry with exponential backoff (`Retry` from urllib3)
- Rate limiting
- `health_check()` method for connectivity validation

```python
# Adding a new connector:
class MyConnector(_BaseConnector):
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.base_url = config.get("url", "")
        # Set self.configured = True when all required fields present
    
    def health_check(self) -> Dict[str, Any]:
        return self._request("GET", "/health")
```

### Integration Types (suite-core/core/integration_models.py)
Add new integrations to `IntegrationType` enum, then wire in `integrations_router.py`:
- Add to `IntegrationType` enum
- Add connector import in `integrations_router.py`
- Add elif case in `test_integration()` and `trigger_sync()` endpoints

### Frontend — aldeci (ACTIVE)
> **⚠️ `suite-ui/aldeci-ui-new/` does NOT exist on disk. All UI work goes into `suite-ui/aldeci/`.**
- Stack: React 18 + Vite 5 + TypeScript 5 + Tailwind 3 + shadcn/ui + Framer Motion
- Design target: Apple HIG-inspired (clean typography, generous whitespace, physics-based animations)
- Navigation target: 5 Workflow Spaces (Mission Control, Discover, Validate, Remediate, Comply) — sidebar restructure pending
- Pages: `suite-ui/aldeci/src/pages/` (grouped by section)
- API client: `suite-ui/aldeci/src/lib/api.ts` — axios with `X-API-Key` header
- Export API namespaces: `dashboardApi`, `integrationsApi`, `findingsApi`, etc.

## Developer Commands

```bash
# Backend
source .venv/bin/activate
python -m uvicorn apps.api.app:create_app --factory --port 8000 --reload

# Frontend (separate terminal)
cd suite-ui/aldeci && npm run dev  # http://localhost:3001

# Testing
make test                          # pytest with 18% coverage gate (CI)
pytest tests/test_<name>.py -v     # single test file
pytest -k "test_integrations" -v   # pattern match

# Formatting
make fmt                           # isort + black

# Demo pipeline
make demo                          # full end-to-end demo

# AI Agent Swarm (Claude Opus 4.6 — UNLEASHED)
./scripts/run-ai-team-unleashed.sh              # All 17 agents
./scripts/run-ai-team-unleashed.sh --agent NAME  # Single agent
./scripts/run-ai-team-unleashed.sh --dry-run     # Show plan
```

## Testing Conventions

- Tests in `tests/` directory, named `test_*.py`
- Markers defined in `pyproject.toml`: `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.e2e`
- Use `conftest.py` fixtures for shared test setup
- Coverage gate: 18% minimum in CI (`--cov-fail-under=18`), 25% in pyproject.toml

## File Structure Conventions

- Routers: `suite-api/apps/api/*_router.py` (FastAPI APIRouter)
- Models: `suite-core/core/*_models.py` (dataclasses, Pydantic, enums)
- Database: `suite-core/core/*_db.py` (SQLite with WAL mode)
- UI Pages (ACTIVE): `suite-ui/aldeci/src/pages/**/*.tsx`
- UI Components: `suite-ui/aldeci/src/components/ui/` (shadcn) and `components/`
- NOTE: `suite-ui/aldeci-ui-new/` does NOT exist on disk
- Agent Definitions: `.claude/agents/*.md` (18 agents incl. ux-architect, all Claude Opus 4.6)
- Agent State: `.claude/team-state/` (sprint board, statuses, debates)

## Key Design Decisions

1. **Multi-LLM Consensus**: GPT-4 + Claude + Gemini with 85% threshold (see `core/llm_providers.py`)
2. **SQLite WAL**: All DBs use WAL mode for concurrent reads
3. **No external message queues**: Event-driven via `core/event_bus.py`
4. **Signed evidence**: RSA-SHA256 signatures via `core/crypto.py`
5. **APP_ID-Centric**: Everything organized under App → Component → Feature hierarchy
6. **CTEM+ dual mode**: 8 native scanners for air-gapped + Switzerland orchestration for external tools

## Build Order (from VISION_TO_ACCOMPLISH.MD)

| Sprint | Goal | Key Deliverables |
|--------|------|-----------------|
| 1 | Demo-Ready Foundation | FAIL Engine ✅, Attack Path Viz ✅, LLM Consensus ✅ |
| 2 | AI Moats | MCP Full Gateway, Single Agent Engine |
| 3 | Compliance & Crypto | Quantum-Secure Signing, Compliance Auto-Mapping |
| 4 | UI Polish | 5 Workflow Spaces nav, 6 new pages, 15 stub rebuilds |
| 5 | Infrastructure | Zero-Gravity Data, Developer Experience |

## 15 Former Stub Pages — Status (verified 2026-03-02)

14/15 pages are now fully wired to real APIs (REAL). 1 page (EvidenceBundles) is PARTIAL — makes real API calls but falls back to demo data on error.
All pages grew from <100 LOC to 258-2091 LOC. No pure stubs remain.

**Action needed**: EvidenceBundles.tsx — remove Math.random() fallback, show error state instead of fake data.

## Common Pitfalls

- Don't create files in `WIP/` — excluded from formatting/linting
- Always add new routers to `apps/api/app.py` `include_router()` calls
- UI environment: `VITE_API_URL` and `VITE_API_KEY` in `.env`
- Backend auth: `X-API-Key` header required (see `dependencies.py`)
- Tag every piece of work with the Vision Pillar it serves (V1-V10)
- Read `docs/VISION_TO_ACCOMPLISH.MD` for complete build specifications
- Read `docs/CTEM_PLUS_IDENTITY.md` for scanner/AutoFix/pipeline reference
- ALdeci is a **CTEM+ platform** — never describe it as "just an aggregator"
- Postman collections: `suite-integrations/postman/enterprise/ALdeci-{1..7}-*.json` (~475 assertions)
