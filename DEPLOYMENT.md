# ALdeci FixOps CTEM+ Enterprise — Deployment Guide

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Port 3000                          │
│            Node.js Production Server                │
│  ┌──────────────┐    ┌──────────────────────────┐   │
│  │ Static Files  │    │ /api/* → Proxy → :8000   │   │
│  │ (React SPA)   │    │ Python FastAPI Backend   │   │
│  └──────────────┘    └──────────────────────────┘   │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │ 400+ REST Endpoints │ 12-Step Brain Pipeline │   │
│  │ Real EPSS/KEV Feeds │ MPTE Pentest Engine    │   │
│  │ Knowledge Graph     │ Compliance Engine      │   │
│  └──────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
```

## Quick Start (Docker)

```bash
# 1. Clone
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# 2. Configure secrets
cp .env.example .env
# Edit .env — set FIXOPS_API_TOKEN and FIXOPS_JWT_SECRET

# 3. Deploy
docker compose up -d

# 4. Access
open http://localhost:3000
```

## Quick Start (Manual)

```bash
# Prerequisites: Python 3.11+, Node.js 20+

# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Install Node dependencies
cd suite-ui/aldeci-ui-new && npm install && cd ../..
npm install  # Root-level for serve.js

# 3. Build frontend
cd suite-ui/aldeci-ui-new && npx vite build && cd ../..

# 4. Configure environment
export FIXOPS_API_TOKEN=$(python3 -c "import secrets; print(f'fixops_sk_{secrets.token_urlsafe(32)}')")
export FIXOPS_JWT_SECRET=$(openssl rand -hex 32)
export FIXOPS_MODE=enterprise
export PYTHONPATH=$(pwd)/suite-api:$(pwd)/suite-api/apps:$(pwd):$(pwd)/suite-core:$(pwd)/suite-attack:$(pwd)/suite-evidence-risk:$(pwd)/suite-integrations

# 5. Start API backend
python3 -m uvicorn api.app:create_app --factory --host 0.0.0.0 --port 8000 --app-dir suite-api/apps &

# 6. Start production server
node serve.js
# → http://localhost:3000
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `FIXOPS_API_TOKEN` | Yes | API authentication key. Generate: `python3 -c "import secrets; print(f'fixops_sk_{secrets.token_urlsafe(32)}')"` |
| `FIXOPS_JWT_SECRET` | Yes | JWT signing secret. Generate: `openssl rand -hex 32` |
| `FIXOPS_MODE` | Yes | Must be `enterprise` for production |
| `API_WORKERS` | No | Uvicorn worker count (default: 4) |
| `LOG_LEVEL` | No | Logging level: debug, info, warning, error (default: info) |
| `FIXOPS_PORT` | No | External port mapping (default: 3000) |

## API Authentication

All API requests require the `X-API-Key` header:

```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:3000/api/v1/analytics/findings
```

## Platform Modules

| Module | Endpoint Prefix | Description |
|---|---|---|
| Finding Explorer | `/api/v1/analytics/findings` | Unified vulnerability browser across all scanners |
| MPTE Engine | `/api/v1/mpte/*` | Micro-pentest validation across 19 phases |
| Brain Pipeline | `/api/v1/brain/*` | 12-step Decision Intelligence Engine |
| Compliance Engine | `/api/v1/compliance-engine/*` | SOC2, PCI-DSS, HIPAA, ISO 27001 |
| Exposure Cases | `/api/v1/cases` | Deduplicated finding lifecycle management |
| Threat Feeds | `/api/v1/feeds/*` | 319K EPSS records, 1536 KEV entries |
| Remediation | `/api/v1/remediation/*` | AI-driven fix recommendations |
| AutoFix | `/api/v1/autofix/*` | Automated remediation with PR generation |
| FAIL Engine | `/api/v1/fail/*` | Focused Attack Impact Learning drills |
| Secrets Detection | `/api/v1/secrets` | Leaked credential scanner |
| SBOM Inventory | `/api/v1/inventory/sbom/*` | Software Bill of Materials |
| SAST Rules | `/api/v1/sast/rules` | 110 static analysis rules |
| Predictions | `/api/v1/predictions` | ML-based breach probability |
| Copilot | `/api/v1/copilot/*` | AI security assistant agents |
| Marketplace | `/api/v1/marketplace/*` | Integration and plugin ecosystem |

## Production Hardening

### For US Defence / Secure Enterprise Deployment:

1. **TLS Termination**: Place behind a reverse proxy (nginx, HAProxy, AWS ALB) with TLS 1.3
2. **Network Segmentation**: Deploy in a private VPC/VLAN with no direct internet access
3. **RBAC**: 8 user roles with team-based access control (built-in)
4. **Audit Trail**: All actions logged with timestamps and user attribution
5. **Rate Limiting**: Configurable per-endpoint rate limits (enabled by default)
6. **Secret Rotation**: Rotate `FIXOPS_API_TOKEN` and `FIXOPS_JWT_SECRET` quarterly
7. **Air-Gap Mode**: All threat feeds can be loaded from local files (no internet required)

### Scaling

```yaml
# Scale API workers
API_WORKERS=8

# Or scale with Docker
docker compose up --scale fixops=3 -d
```

## Health Check

```bash
curl http://localhost:3000/api/v1/health
# {"status": "healthy", "mode": "enterprise", "version": "..."}
```

## Support

- Repository: https://github.com/DevOpsMadDog/Fixops
- Branch: `features/intermediate-stage`
