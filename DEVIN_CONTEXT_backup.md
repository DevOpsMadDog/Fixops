# ALdeci — Full Application Context for Devin.ai

> **Last updated**: 2026-02-19
> **Branch**: `features/intermediate-stage`
> **Formerly known as**: FixOps

---

## 1. What is ALdeci?

ALdeci is a **security vulnerability management and risk assessment platform**. It ingests vulnerabilities from multiple feeds (NVD, CISA KEV, EPSS, GitHub Advisories, OSV, ExploitDB), runs AI-powered analysis, simulates attacks, scores risk, and provides a unified dashboard for security teams.

**Key capabilities:**
- Real-time vulnerability feed ingestion and correlation
- Knowledge Graph Brain for CVE relationship mapping
- AI-powered micro-pentesting (MPTE engine)
- Attack simulation and reachability analysis
- Evidence bundling and compliance reporting (SOC2, ISO27001)
- SBOM normalization (CycloneDX, SPDX)
- Multi-LLM support (OpenAI, Claude, Gemini)

---

## 2. Architecture — 6 Suites (Monolithic Mode)

The app uses a **6-suite microservice architecture** that currently runs in **monolithic mode** — all suites loaded into a single FastAPI process on port 8000.

| Suite | Directory | Port (future) | Purpose |
|-------|-----------|---------------|---------|
| **API** | `suite-api/` (41 .py) | 8000 | FastAPI app, all REST endpoints, 27 routers |
| **Core** | `suite-core/` (322 .py) | 8001 | Business logic, CLI, Knowledge Graph, pipeline stages |
| **Attack** | `suite-attack/` (13 .py) | 8002 | MPTE engine, micro-pentest, attack simulation |
| **Feeds** | `suite-feeds/` (3 .py) | 8003 | NVD, CISA KEV, EPSS, GitHub Advisories, OSV ingest |
| **Evidence-Risk** | `suite-evidence-risk/` (69 .py) | 8004 | Evidence packager, risk scoring, compliance |
| **Integrations** | `suite-integrations/` (23 .py) | 8005 | Jira, Slack, SBOM normalization (lib4sbom) |

### Entry Point

```
suite-api/apps/api/app.py  →  `app` (FastAPI instance)
```

This file imports routers from ALL other suites. The `app` object is the uvicorn target.

### Critical: PYTHONPATH

Every suite directory must be on `PYTHONPATH` for imports to resolve:

```bash
PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"
```

**Why?** The code uses `from apps.api.app import ...`, `from core.engine import ...`, etc.  
With the suite layout, `suite-api/apps/api/app.py` needs `suite-api/` on the path so Python finds `apps.api.app`.

### Critical: No `__init__.py` in `api/` directories

All suites use **implicit namespace packages**. Do NOT add `__init__.py` to any `api/` directory or Python will treat the first one found as a regular package and break imports from other suites.

---

## 3. Frontend (suite-ui)

| Tech | Version |
|------|---------|
| React | 18.2 |
| TypeScript | 5.3 |
| Vite | 5.0.11 |
| Tailwind CSS | 3.4.1 |
| shadcn/ui | Copy/paste components (NOT a library) |
| Radix UI | 18 primitives |
| Zustand | 4.4.7 (state management) |
| react-router-dom | 6.21.2 |

**Location**: `suite-ui/aldeci/` — 4,118 TS/TSX files, 56 screens  
**Dev server**: `cd suite-ui/aldeci && npm run dev` → port **3001**  
**API proxy**: Configured in Vite to proxy `/api/*` → `http://localhost:8000`

### Key Pages

`Dashboard`, `NerveCenter`, `IntelligenceHub`, `AttackLab`, `DecisionEngine`, `EvidenceVault`, `DataFabric`, `RemediationCenter`, `Copilot`, `Settings`

---

## 4. How to Run Locally

### Backend
```bash
cd /path/to/Fixops
export PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations"
uvicorn apps.api.app:app --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd suite-ui/aldeci
npm install
npm run dev  # → http://localhost:3001
```

### Environment Variables
- `FIXOPS_API_TOKEN` — API key for authenticated endpoints (default: `demo-token-12345`)
- `FIXOPS_MODE` — `enterprise` or `demo`
- `FIXOPS_DISABLE_TELEMETRY` — set to `1` to disable
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_AI_API_KEY` — for LLM providers

---

## 5. Docker

**Dockerfile**: `docker/Dockerfile`  
**Entrypoint**: `scripts/docker-entrypoint.sh`  
**CMD**: `["api-only"]` → runs `uvicorn apps.api.app:app`

The Dockerfile copies ONLY `suite-*` directories (no legacy code). PYTHONPATH is set inside the image.

```bash
docker build -f docker/Dockerfile -t aldeci .
docker run -p 8000:8000 -e FIXOPS_API_TOKEN=my-key aldeci
```

---

## 6. CI/CD Workflows

| Workflow | File | Purpose |
|----------|------|---------|
| **CI** | `.github/workflows/ci.yml` | Lint, format, pytest |
| **QA** | `.github/workflows/qa.yml` | Mypy, extended tests |
| **Docker Build** | `.github/workflows/docker-build.yml` | Build image, smoke test CLI, verify suite arch |
| **FixOps CI** | `.github/workflows/fixops-ci.yml` | Compile check, API smoke test |
| **CodeQL** | `.github/workflows/codeql.yml` | Security scanning |
| Provenance | `.github/workflows/provenance.yml` | ⚠️ References removed `cli/` dir |
| Release Sign | `.github/workflows/release-sign.yml` | ⚠️ References removed `cli/` dir |
| Repro Verify | `.github/workflows/repro-verify.yml` | ⚠️ References removed `cli/` dir |
| FixOps Pipeline | `.github/workflows/fixops_pipeline.yml` | ⚠️ References `fixops.cli` module |

**⚠️ Workflows marked with ⚠️ may need updating or disabling** — they reference legacy `cli/` and `fixops/` directories that no longer exist.

---

## 7. Testing

- **Framework**: pytest
- **Config**: `pyproject.toml`
- **Test dir**: `tests/` (239 .py files)
- **Run**: `PYTHONPATH=".:suite-api:suite-core:suite-attack:suite-feeds:suite-evidence-risk:suite-integrations" pytest tests/ -v`

---

## 8. Repository Structure (Post-Cleanup)

```
Fixops/
├── suite-api/           # FastAPI app + 27 REST routers (41 .py)
├── suite-core/          # Business logic, CLI, KG Brain (322 .py)
├── suite-attack/        # MPTE, micro-pentest, simulations (13 .py)
├── suite-feeds/         # Vulnerability feed ingestors (3 .py)
├── suite-evidence-risk/ # Evidence bundler, risk scoring (69 .py)
├── suite-integrations/  # Jira, Slack, SBOM normalization (23 .py)
├── suite-ui/            # React frontend (4,118 ts/tsx)
│   └── aldeci/          # Vite project root
├── tests/               # pytest tests (239 .py)
├── scripts/             # Utility scripts, docker-entrypoint.sh
├── docker/              # Dockerfile
├── docs/                # Documentation
├── .github/             # CI workflows + CodeQL config
├── pyproject.toml       # Python project config
├── requirements.txt     # Python dependencies
├── requirements-test.txt
├── Makefile
├── README.md
├── sitecustomize.py     # Python startup hook
├── usercustomize.py     # Python user startup hook
└── docker-compose.demo.yml
```

---

## 9. What Was Cleaned Up (and Why)

The `docker/Dockerfile` previously had hardcoded `COPY` for 18+ legacy root directories. These were OLD monolith code — completely different from the active `suite-*` code (`apps/api/app.py` vs `suite-api/apps/api/app.py` had 846 diff lines). The fix: rewrite Dockerfile to use suite architecture, remove stale code.

### Removed directories (preserved in `clutter-legacy` branch):
`agents/`, `apps/`, `backend/`, `cli/`, `config/`, `core/`, `domain/`, `evidence/`, `fixops-enterprise/`, `fixops/`, `integrations/`, `lib4sbom/`, `new_apps/`, `new_backend/`, `risk/`, `samples/`, `services/`, `simulations/`, `telemetry/`, `archive/`, `archive_not_needed/`, `suite-ui1/`, `data/`

### Devin's fixes ported to suite versions:
1. **Collision detection** in `suite-evidence-risk/evidence/packager.py` — duplicate filename handling
2. **Metadata guard** in `suite-integrations/lib4sbom/normalizer.py` — `(doc.get("metadata") or {}).get("tools")`

---

## 10. Guidelines for Devin

1. **ONLY edit files under `suite-*/`** — that's the active codebase
2. **Never add `__init__.py`** to any `api/` directory (breaks namespace packages)
3. **Always set PYTHONPATH** to include all 6 suite dirs when running Python
4. **Dockerfile** at `docker/Dockerfile` copies only `suite-*` dirs
5. **Legacy code** preserved in `clutter-legacy` branch for reference
6. **⚠️ 4 workflows** (provenance, release-sign, repro-verify, fixops_pipeline) reference deleted dirs
7. **Database files** (`.db`) are gitignored — never commit them
8. **Python version**: 3.11 | **shadcn/ui**: copy/paste components, not npm-installed
