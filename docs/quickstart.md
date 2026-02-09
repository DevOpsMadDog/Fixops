# ALdeci Quick Start Guide

Get ALdeci running locally in under 10 minutes.

## Prerequisites

- Python 3.11+ (tested with 3.14)
- Node.js 18+ & npm
- Git

## 1. Clone & Install

```bash
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

## 2. Start the Backend (6 Suites)

Each suite runs on its own port:

```bash
# Terminal 1 — API Gateway (port 8000)
cd suite-api && uvicorn api.app:app --port 8000 --reload

# Terminal 2 — Core (port 8001)
cd suite-core && uvicorn api.app:app --port 8001 --reload

# Terminal 3 — Attack (port 8002)
cd suite-attack && uvicorn api.app:app --port 8002 --reload

# Terminal 4 — Feeds (port 8003)
cd suite-feeds && uvicorn api.app:app --port 8003 --reload

# Terminal 5 — Evidence & Risk (port 8004)
cd suite-evidence-risk && uvicorn api.app:app --port 8004 --reload

# Terminal 6 — Integrations (port 8005)
cd suite-integrations && uvicorn api.app:app --port 8005 --reload
```

Or use the convenience script:

```bash
python3 run_all_suites.py
```

## 3. Start the Frontend

```bash
cd suite-ui/aldeci
npm install
npm run dev          # → http://localhost:5173
```

## 4. Verify Health

```bash
curl http://localhost:8000/health
# {"status":"healthy","version":"..."}
```

## 5. First Scan — Upload an SBOM

```bash
curl -X POST http://localhost:8000/api/v1/sbom/upload \
  -H "Content-Type: application/json" \
  -d '{"format":"cyclonedx","content":{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}}'
```

## 6. Check Vulnerability Feeds

```bash
# Search NVD
curl "http://localhost:8003/api/v1/feeds/nvd/search?keyword=log4j&limit=5"

# EPSS scores
curl "http://localhost:8003/api/v1/feeds/epss/scores?cves=CVE-2021-44228"

# CISA KEV
curl "http://localhost:8003/api/v1/feeds/kev/recent?limit=5"
```

## 7. Run the Brain Pipeline

```bash
curl -X POST http://localhost:8001/api/v1/brain/pipeline/run \
  -H "Content-Type: application/json" \
  -d '{"org_id":"demo","options":{"max_cves":10}}'
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_AUTH_MODE` | `dev` | `dev` = no auth, `enforced` = JWT required |
| `FIXOPS_JWT_SECRET` | random | Secret for JWT signing (HS256) |
| `FIXOPS_ALLOWED_ORIGINS` | localhost | Comma-separated CORS origins |
| `FIXOPS_CACHE_URL` | (none) | Redis URL for caching, e.g. `redis://localhost:6379/0` |
| `NVD_API_KEY` | (none) | NVD API key for higher rate limits |
| `OPENAI_API_KEY` | (none) | OpenAI key for AI copilot |
| `ANTHROPIC_API_KEY` | (none) | Anthropic key for AI copilot |

## Architecture Overview

```
suite-api (8000)          ← API gateway, auth, routing
suite-core (8001)         ← Knowledge Graph, Brain Pipeline, ML
suite-attack (8002)       ← SAST, DAST, CSPM, container scanning
suite-feeds (8003)        ← NVD, KEV, EPSS, ExploitDB, OSV
suite-evidence-risk (8004)← SOC2 evidence, risk scoring
suite-integrations (8005) ← Jira, Slack, Snyk, SonarQube, etc.
suite-ui (5173)           ← React + TypeScript UI (56 screens)
```

## Next Steps

- [Connect your security tools](integrations.md)
- [Troubleshooting](troubleshooting.md)

