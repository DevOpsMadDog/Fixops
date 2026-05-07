# ALdeci CTEM+ Platform — Customer Install Guide

## Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Docker | 24+ |
| Docker Compose plugin | v2.20+ (`docker compose version`) |
| RAM | 4 GB free |
| Disk | 8 GB free |
| OS | macOS, Linux, or Windows (WSL2) |

## 3-Command Quick Start

```bash
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
docker compose up -d
```

The stack pulls images and starts automatically. First boot takes 2–4 minutes while
Docker builds the API and UI images.

## First Login

Once the stack is healthy, open your browser:

```
http://localhost:3000/executive
```

Default API token (set in `docker-compose.yml`):

```
aldeci-demo-token
```

Use this token in any API call:

```bash
curl -H "X-API-Key: aldeci-demo-token" http://localhost:8000/health
```

## Set a Custom Token

Create a `.env` file at the repo root before running `docker compose up`:

```bash
cp .env.example .env
# Edit .env — set FIXOPS_API_TOKEN and FIXOPS_JWT_SECRET
```

Generate a secure token:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Required variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `FIXOPS_API_TOKEN` | API authentication token | `aldeci-demo-token` |
| `FIXOPS_JWT_SECRET` | JWT signing secret | _(empty — set in prod)_ |
| `ALDECI_PORT` | API port | `8000` |
| `ALDECI_UI_PORT` | UI port | `3000` |

Optional LLM variables (leave blank for air-gapped / offline mode):

| Variable | Purpose |
|----------|---------|
| `OPENAI_API_KEY` | GPT-4o consensus |
| `ANTHROPIC_API_KEY` | Claude consensus |
| `OPENROUTER_API_KEY` | Qwen / DeepSeek / Kimi (free tier) |

## Verify Health (within 30 s)

```bash
./scripts/demo-healthcheck.sh --quick
```

Expected output:

```
  API Health (200)
  Brain Pipeline Stats (200)
  MCP Tools Discovery (200)
```

Full suite (44+ checks across all 8 scanners):

```bash
./scripts/demo-healthcheck.sh
```

## Import a Repo

After login, go to:

```
http://localhost:3000/import
```

Upload a `.zip` of your repo or paste a GitHub URL. The Brain Pipeline runs
all 8 native scanners (SAST, DAST, Secrets, Container, CSPM, IaC, Malware,
API Fuzzer) and populates the Executive dashboard automatically.

## Port Map

| Port | Service |
|------|---------|
| `3000` | React UI (nginx) |
| `8000` | FastAPI backend |
| `5678` | n8n workflow engine |

## Troubleshooting

**Port conflict**

```bash
lsof -i :8000   # find what's using the port
ALDECI_PORT=8001 docker compose up -d   # use alternate port
```

**Container not starting**

```bash
docker compose logs aldeci-api   # API logs
docker compose logs aldeci-ui    # UI logs
```

**Full reset (wipe all data)**

```bash
docker compose down -v
docker compose up -d
```

**Check container health**

```bash
docker compose ps
# STATUS column should show "healthy" for aldeci-api
```

**Startup takes >60 s** — Docker may be pulling base images on first run.
After the first build, subsequent starts take under 10 s.
