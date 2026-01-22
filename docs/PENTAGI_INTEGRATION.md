# PentAGI Integration Guide

This guide covers deploying FixOps with integrated PentAGI for autonomous micro-pentest capabilities.

## Overview

PentAGI is an autonomous AI penetration testing agent that can validate vulnerability exploitability. When integrated with FixOps, it enables automated security verification directly from the Risk Graph UI.

The integration is designed as a **Docker Compose layer** that can be added to any FixOps deployment variant.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        FixOps Stack                              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐              │
│  │  FixOps API │  │  Risk Graph │  │   Sidecars  │              │
│  │   :8000     │  │    UI       │  │             │              │
│  └──────┬──────┘  └─────────────┘  └─────────────┘              │
│         │                                                        │
│         │ HTTP/HTTPS                                             │
│         ▼                                                        │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │                    PentAGI Layer                             ││
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          ││
│  │  │   PentAGI   │  │  pgvector   │  │   Scraper   │          ││
│  │  │   :8443     │  │   :5433     │  │   :9443     │          ││
│  │  └─────────────┘  └─────────────┘  └─────────────┘          ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Prerequisites

- Docker 20.10+ and Docker Compose v2
- At least one LLM API key (OpenAI, Anthropic, or Google)
- 8GB+ RAM recommended
- Ports 8443, 5433, 9443 available

## Quick Start

```bash
# 1. Clone FixOps (if not already done)
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# 2. Copy environment files
cp .env.example .env
cp env.pentagi.example .env.pentagi

# 3. Configure LLM API keys in .env.pentagi
# Edit .env.pentagi and add at least one:
#   OPENAI_API_KEY=sk-...
#   ANTHROPIC_API_KEY=sk-ant-...
#   GOOGLE_API_KEY=...

# 4. Start FixOps with PentAGI
make up-pentagi

# 5. Verify services are running
curl -k https://localhost:8443/health
curl http://localhost:8000/health
```

## Deployment Variants

PentAGI can be added as a layer to any FixOps docker-compose file:

| Command | Base Compose File | Use Case |
|---------|-------------------|----------|
| `make up-pentagi` | docker-compose.yml | Default development/demo |
| `make up-pentagi-enterprise` | docker-compose.enterprise.yml | Enterprise with ChromaDB |
| `make up-pentagi-demo` | docker-compose.demo.yml | Demo with telemetry |
| `make up-pentagi-deployment` | deployment-packs/docker/docker-compose.yml | Production deployment |

You can also use the `BASE_COMPOSE` variable for custom compose files:

```bash
make up-pentagi BASE_COMPOSE=my-custom-compose.yml
```

Or run manually:

```bash
docker compose -f docker-compose.yml -f docker-compose.pentagi.yml --env-file .env.pentagi up -d
```

## Configuration

### Environment Variables

All PentAGI configuration is in `.env.pentagi`. Key settings:

| Variable | Default | Description |
|----------|---------|-------------|
| `PENTAGI_IMAGE` | `vxcontrol/pentagi:latest` | Docker image to use |
| `OPENAI_API_KEY` | - | OpenAI API key |
| `ANTHROPIC_API_KEY` | - | Anthropic API key |
| `GOOGLE_API_KEY` | - | Google Gemini API key |
| `PENTAGI_LISTEN_PORT` | `8443` | PentAGI HTTPS port |
| `PENTAGI_DB_LISTEN_PORT` | `5433` | PostgreSQL port |
| `PENTAGI_USE_SSL` | `true` | Enable HTTPS |
| `PENTAGI_DEBUG` | `false` | Enable debug logging |

### Using Your Own Fork (Air-Gapped/Offline)

For fully offline operation without VXControl Cloud SDK:

```bash
# Use the DevOpsMadDog fork with VXControl Cloud SDK removed
export PENTAGI_IMAGE=ghcr.io/devopsmaddog/pentagi_fork:latest
make up-pentagi
```

The fork at [DevOpsMadDog/pentagi_fork](https://github.com/DevOpsMadDog/pentagi_fork) has:
- VXControl Cloud SDK completely removed
- No phone-home to update.pentagi.com or support.pentagi.com
- Local installation ID generation
- Automated upstream sync workflows
- Guard checks to prevent SDK reintroduction

## Services

### PentAGI (pentagi)

The main autonomous penetration testing agent.

- **Port:** 8443 (HTTPS with self-signed SSL)
- **Health check:** `curl -k https://localhost:8443/health`
- **API docs:** `https://localhost:8443/docs`

### PostgreSQL with pgvector (pentagi-db)

Vector database for PentAGI memory and embeddings.

- **Port:** 5433
- **Database:** pentagidb
- **User:** pentagi (configurable)

### Web Scraper (pentagi-scraper)

Web scraping service for reconnaissance.

- **Port:** 9443 (HTTPS)
- **Shared memory:** 2GB for browser instances

## Security Considerations

### Docker Socket Access

PentAGI requires Docker socket access to spawn sandboxed containers for exploit execution:

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

This is necessary for PentAGI's sandboxed execution model but grants significant privileges. In production:
- Use Docker-in-Docker or a dedicated Docker host
- Apply AppArmor/SELinux profiles
- Use network policies to restrict container egress

### Self-Signed SSL

PentAGI uses self-signed certificates by default. For production:
- Mount your own certificates to `/opt/pentagi/ssl`
- Or use a reverse proxy (nginx/traefik) with proper TLS termination

### Network Isolation

The PentAGI services run on a dedicated `pentagi-network` but also join the default network to communicate with FixOps. Review network policies for your environment.

## Troubleshooting

### PentAGI not starting

```bash
# Check logs
make logs-pentagi

# Or manually
docker compose -f docker-compose.yml -f docker-compose.pentagi.yml logs pentagi
```

### Database connection issues

```bash
# Check pgvector is running
docker ps | grep pentagi-db

# Check database logs
docker logs pentagi-db
```

### SSL certificate errors

PentAGI uses self-signed certificates. Use `-k` with curl:

```bash
curl -k https://localhost:8443/health
```

### Port conflicts

If ports are in use, configure alternatives in `.env.pentagi`:

```bash
PENTAGI_LISTEN_PORT=9443
PENTAGI_DB_LISTEN_PORT=5434
PENTAGI_SCRAPER_LISTEN_PORT=9444
```

## Stopping Services

```bash
# Stop default variant
make down-pentagi

# Stop enterprise variant
make down-pentagi-enterprise

# Stop with custom base compose
make down-pentagi BASE_COMPOSE=docker-compose.enterprise.yml
```

## Upgrading

### Upgrading PentAGI

```bash
# Pull latest images
docker compose -f docker-compose.yml -f docker-compose.pentagi.yml pull

# Restart services
make down-pentagi
make up-pentagi
```

### Upgrading from Fork

If using the DevOpsMadDog fork, the fork automatically syncs with upstream weekly. To get the latest:

```bash
# Pull latest fork image
docker pull ghcr.io/devopsmaddog/pentagi_fork:latest

# Restart
make down-pentagi
make up-pentagi
```

## Integration with FixOps

### API Integration

FixOps communicates with PentAGI via its REST API:

```python
# Example: Trigger micro-pentest from FixOps
import requests

response = requests.post(
    "https://pentagi:8443/api/v1/flows",
    json={
        "target": "https://example.com",
        "cve": "CVE-2021-44228",
        "scope": "verify_exploitability"
    },
    verify=False  # Self-signed cert
)
```

### Environment Variables for FixOps

Configure FixOps to use PentAGI:

```bash
# In .env or docker-compose environment
PENTAGI_URL=https://pentagi:8443
PENTAGI_VERIFY_SSL=false
```

## Related Documentation

- [FixOps README](../README.md)
- [API Reference](API_CLI_REFERENCE.md)
- [Enterprise Features](ENTERPRISE_FEATURES.md)
- [PentAGI Fork](https://github.com/DevOpsMadDog/pentagi_fork)
