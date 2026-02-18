# ALdeci Docker Guide

This guide explains all Docker configurations available in ALdeci and how to use them.

## Quick Reference

| Docker Compose File | Purpose | API Port | Default Token | Use Case |
|---------------------|---------|----------|---------------|----------|
| `docker-compose.yml` | Main development stack | 8000 | `demo-token` | Local development with sidecars |
| `docker-compose.demo.yml` | Demo with telemetry | 8000 | (env var) | Demos with OpenTelemetry |
| `docker-compose.enterprise.yml` | Enterprise with ChromaDB | 8000 | `enterprise-token` | Enterprise features testing |
| `docker-compose.vc-demo.yml` | VC Demo | 8000 | `demo-token` | Investor demonstrations |
| `deployment-packs/docker/docker-compose.yml` | Production template | 8000 | (env var) | Production deployments |
| `deployment/docker-compose.enterprise.yml` | Full enterprise stack | 8000 | (env var) | Production enterprise |

| Dockerfile | Purpose | Port | Default Token |
|------------|---------|------|---------------|
| `Dockerfile` | Main optimized image | 8000 | `demo-token-12345` |
| `Dockerfile.interactive` | Interactive testing | 8000 | `demo-token-12345` |
| `Dockerfile.demo` | VC Demo image | 8000 | `demo-token` |
| `Dockerfile.enterprise` | Enterprise with ChromaDB | 8000 | `enterprise-token` |
| `Dockerfile.simple` | Minimal demo image | 8000 | `demo-token` |
| `Dockerfile.sidecar` | Sidecar for demos/tests | N/A | `demo-token` |
| `Dockerfile.risk-graph` | Risk Graph UI (Next.js) | 3000 | `demo-token` |

## Health Endpoints

All ALdeci containers expose health check endpoints:

- `/health` - Simple liveness check (root level)
- `/api/v1/health` - Full health check with version info
- `/api/v1/ready` - Readiness probe with dependency checks

## Authentication

ALdeci uses token-based authentication by default. The API token is set via the `FIXOPS_API_TOKEN` environment variable.

To authenticate API requests, include the token in the `X-API-Key` header:

```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/api/v1/status
```

Note: Health/liveness endpoints (`/health`, `/api/v1/health`) do not require authentication and can be used for container health checks.

---

## Docker Compose Configurations

### 1. Main Development Stack (`docker-compose.yml`)

**Purpose:** Primary development environment with the ALdeci API and optional sidecars.

**Services:**
- `aldeci` - Main API server
- `aldeci-demo` - Interactive demo sidecar (profile: `demo`)
- `aldeci-smoke` - Smoke test runner (profile: `test`)
- `aldeci-feeds` - Real-time feed fetcher (profile: `feeds`)
- `aldeci-micropentest` - Micro penetration testing (profile: `pentest`)
- `risk-graph-ui` - Risk Graph visualization (profile: `ui`)

**Usage:**
```bash
# Start main API only
docker compose up -d

# Start with demo sidecar
docker compose --profile demo up -d

# Start with Risk Graph UI
docker compose --profile ui up -d

# Start all services
docker compose --profile demo --profile ui --profile feeds up -d
```

**Configuration:**
- Port: `8000`
- Token: Set via `FIXOPS_API_TOKEN` env var (default: `demo-token`)
- Mode: `demo`

---

### 2. Demo with Telemetry (`docker-compose.demo.yml`)

**Purpose:** Demo environment with OpenTelemetry collector for observability.

**Services:**
- `collector` - OpenTelemetry collector
- `api` - ALdeci API with telemetry enabled
- `graph` - Graph worker for dependency analysis
- `dashboard` - Nginx dashboard

**Usage:**
```bash
docker compose -f docker-compose.demo.yml up -d
```

**Configuration:**
- API Port: `8000`
- Dashboard Port: `8080`
- OTLP Port: `4318`

---

### 3. Enterprise with ChromaDB (`docker-compose.enterprise.yml`)

**Purpose:** Enterprise mode with vector store (ChromaDB) for semantic search and ML features.

**Services:**
- `aldeci-enterprise` - Enterprise API with ChromaDB integration

**Usage:**
```bash
docker compose -f docker-compose.enterprise.yml up -d
```

**Configuration:**
- Port: `8000`
- Token: `enterprise-token`
- Mode: `enterprise`
- Vector Store: ChromaDB (persisted to `aldeci-chroma-data` volume)

**Features Enabled:**
- Semantic search via ChromaDB
- Sentence transformer embeddings
- Full enterprise feature set

---

### 4. VC Demo (`docker-compose.vc-demo.yml`)

**Purpose:** Self-contained environment for investor demonstrations.

**Usage:**
```bash
docker compose -f docker-compose.vc-demo.yml up -d

# Run demo inside container
docker exec -it aldeci-vc-demo python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty
```

**Configuration:**
- Port: `8000`
- Token: `demo-token`
- Mode: `demo`

---

### 5. Production Deployment Pack (`deployment-packs/docker/docker-compose.yml`)

**Purpose:** Production-ready template with MongoDB, Redis, and optional monitoring.

**Services:**
- `mongodb` - Evidence lake storage
- `redis` - Caching layer
- `aldeci-backend` - Production API
- `aldeci-frontend` - Web UI (profile: `frontend`)
- `nginx` - Reverse proxy (profile: `nginx`)
- `prometheus` - Metrics (profile: `monitoring`)
- `grafana` - Dashboards (profile: `monitoring`)

**Prerequisites:**
Set required environment variables before starting:
```bash
export MONGO_PASSWORD="your-secure-password"
export REDIS_PASSWORD="your-secure-password"
export SECRET_KEY="your-secret-key"
```

Or use the setup wizard:
```bash
./scripts/setup-wizard.sh
```

**Usage:**
```bash
cd deployment-packs/docker
docker compose up -d

# With frontend
docker compose --profile frontend up -d

# With monitoring
docker compose --profile monitoring up -d
```

**Configuration:**
- Backend Port: `8000` (configurable via `BACKEND_PORT`)
- Frontend Port: `3000` (configurable via `FRONTEND_PORT`)
- Grafana Port: `3001`

---

### 6. Full Enterprise Stack (`deployment/docker-compose.enterprise.yml`)

**Purpose:** Production enterprise deployment with HA, monitoring, and security.

**Services:**
- `aldeci-api` - API server (3 replicas)
- `aldeci-reachability` - Reachability analyzer (5 replicas)
- `aldeci-threat-intel` - Threat intelligence engine
- `postgres` - Primary database
- `postgres-replica` - Read replica
- `redis` - Caching with Sentinel HA
- `otel-collector` - OpenTelemetry
- `prometheus` - Monitoring
- `grafana` - Dashboards
- `nginx` - Load balancer

**Prerequisites:**
```bash
export POSTGRES_PASSWORD="your-secure-password"
export GRAFANA_PASSWORD="your-admin-password"
```

**Usage:**
```bash
cd deployment
docker compose -f docker-compose.enterprise.yml up -d
```

**Configuration:**
- API Port: `8000`
- Grafana Port: `3000`
- Prometheus Port: `9090`
- HTTPS: `443` (via nginx)

---

## Dockerfiles

### Main Image (`Dockerfile`)

**Purpose:** Optimized production image for the ALdeci API.

**Build:**
```bash
docker build -t aldeci:latest .
```

**Run:**
```bash
# API server mode (default)
docker run -p 8000:8000 aldeci:latest

# Interactive mode
docker run -it aldeci:latest interactive

# Demo mode
docker run -it aldeci:latest demo

# CLI command
docker run aldeci:latest cli demo --mode demo
```

**Modes:**
- `api-only` - Start only the API server (default)
- `interactive` - Interactive API tester
- `demo` - ALDECI animated demo
- `test-all` - Run all API tests
- `cli <args>` - Run CLI commands
- `shell` - Bash shell

---

### Interactive Testing (`Dockerfile.interactive`)

**Purpose:** Full-featured image for interactive testing and development.

Same as main `Dockerfile` but includes additional tools (nano, vim, less).

---

### Enterprise Image (`Dockerfile.enterprise`)

**Purpose:** Enterprise image with ChromaDB and sentence transformers.

**Build:**
```bash
docker build -f Dockerfile.enterprise -t aldeci:enterprise .
```

**Features:**
- ChromaDB vector store
- Sentence transformer embeddings
- Full enterprise dependencies

---

### Sidecar Image (`Dockerfile.sidecar`)

**Purpose:** Lightweight container for running demos and tests against a ALdeci API.

**Build:**
```bash
docker build -f Dockerfile.sidecar -t aldeci-sidecar .
```

**Usage:**
```bash
# Full demo
docker run --network host -e FIXOPS_BASE_URL=http://localhost:8000 aldeci-sidecar

# Specific scenario
docker run --network host -e FIXOPS_BASE_URL=http://localhost:8000 aldeci-sidecar python demo_sidecar.py run-scenario --cve CVE-2021-44228
```

---

### Risk Graph UI (`Dockerfile.risk-graph`)

**Purpose:** Next.js application for interactive risk graph visualization.

**Build:**
```bash
docker build -f Dockerfile.risk-graph -t aldeci-risk-graph \
  --build-arg NEXT_PUBLIC_FIXOPS_API_URL=http://localhost:8000 \
  --build-arg NEXT_PUBLIC_FIXOPS_API_TOKEN=demo-token .
```

**Run:**
```bash
docker run -p 3000:3000 aldeci-risk-graph
```

---

## Common Tasks

### Verify Container is Running

```bash
# Check health
curl http://localhost:8000/health

# Check with authentication
curl -H "X-API-Key: demo-token" http://localhost:8000/api/v1/status
```

### Run Pipeline After Starting Container

```bash
export FIXOPS_API_TOKEN="demo-token"

# Upload artifacts (note: content-type is required)
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -F "file=@simulations/demo_pack/sbom.json;type=application/json" http://localhost:8000/inputs/sbom
curl -H "X-API-Key: $FIXOPS_API_TOKEN" -F "file=@simulations/demo_pack/scanner.sarif;type=application/json" http://localhost:8000/inputs/sarif

# Run pipeline
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/pipeline/run | jq
```

### View Logs

```bash
# Docker Compose
docker compose logs -f aldeci

# Single container
docker logs -f aldeci-api
```

### Check Published Ports

```bash
docker compose ps
```

---

## Troubleshooting

### Container Won't Start

1. Check if port 8000 is already in use:
   ```bash
   lsof -i :8000
   ```

2. Check container logs:
   ```bash
   docker compose logs aldeci
   ```

3. Verify environment variables are set:
   ```bash
   docker compose config
   ```

### Authentication Errors

1. Verify the token matches what's configured:
   ```bash
   # Check what token the container expects
   docker compose exec aldeci env | grep FIXOPS_API_TOKEN
   ```

2. Ensure you're using the correct header:
   ```bash
   curl -H "X-API-Key: YOUR_TOKEN" http://localhost:8000/api/v1/status
   ```

### Health Check Failing

1. Wait for the container to fully start (can take 30-60 seconds)
2. Check if dependencies are healthy:
   ```bash
   docker compose ps
   curl http://localhost:8000/api/v1/ready
   ```

---

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `FIXOPS_API_TOKEN` | API authentication token | varies by compose file |
| `FIXOPS_MODE` | Operating mode (`demo`/`enterprise`) | `demo` |
| `FIXOPS_DISABLE_TELEMETRY` | Disable OpenTelemetry | `1` (disabled) |
| `FIXOPS_LOG_LEVEL` | Logging level | `warning` |
| `MONGO_PASSWORD` | MongoDB password | (required for production) |
| `REDIS_PASSWORD` | Redis password | (required for production) |
| `SECRET_KEY` | Application secret key | (required for production) |
| `OPENAI_API_KEY` | OpenAI API key | (optional) |
| `ANTHROPIC_API_KEY` | Anthropic API key | (optional) |
| `GOOGLE_API_KEY` | Google API key | (optional) |
