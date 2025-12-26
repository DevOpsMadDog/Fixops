# ALDECI Demo Scripts

This directory contains the animated demo scripts for showcasing FixOps capabilities.

## Scripts Overview

### aldeci-demo-runner.sh

The main animated demo runner with super classy visuals covering all 7 Core Capability Areas.

**Features:**
- Matrix rain effects, neon glow, cyberpunk-style visuals
- Animated Micro-Pentest Engine with step-by-step exploit validation
- Animated Reachability Analysis with ASCII attack path visualization
- Multi-LLM Consensus display with 4 AI providers
- Customer customization for applications and compliance frameworks
- 8-phase demo flow covering all capabilities

**Usage:**
```bash
# Direct execution
./scripts/aldeci-demo-runner.sh

# With Docker
docker build -f Dockerfile.interactive -t aldeci-demo .
docker run -it aldeci-demo demo
```

**Demo Phases:**
1. Ingestion - SBOM/SARIF/CVE/VEX upload
2. Analysis - Correlation and deduplication
3. Micro-Pentest - Automated exploit validation
4. Reachability - Attack path mapping
5. Decisions - Multi-LLM consensus
6. Integrations - Jira/Slack/GitHub
7. Remediation - SLA tracking and bulk operations
8. Compliance - Framework assessments

### fixops-interactive.sh

Interactive API and CLI tester for all 300+ endpoints.

**Features:**
- Sample input generation for every endpoint
- Interactive editing before API calls
- Option to load local files for testing
- Menu-driven interface for all API categories
- "Run All Tests" mode for automated validation

**Usage:**
```bash
# Direct execution
./scripts/fixops-interactive.sh

# With Docker
docker build -f Dockerfile.interactive -t aldeci-demo .
docker run -it aldeci-demo interactive
```

### docker-entrypoint.sh

Docker entrypoint script that handles different run modes.

**Available Modes:**
- `interactive` - Start interactive API tester (default)
- `api-only` - Start only the API server
- `demo` - Start ALDECI animated demo runner
- `test-all` - Run all API tests automatically
- `cli <args>` - Run FixOps CLI with arguments
- `shell` - Start a bash shell

**Usage:**
```bash
# Interactive mode (default)
docker run -it aldeci-demo

# API-only mode
docker run -it aldeci-demo api-only

# Demo mode
docker run -it aldeci-demo demo

# CLI mode
docker run -it aldeci-demo cli --help

# Shell mode
docker run -it aldeci-demo shell
```

## Docker Image

Build the Docker image:
```bash
docker build -f Dockerfile.interactive -t aldeci-demo .
```

Run with different modes:
```bash
# Interactive API tester
docker run -it aldeci-demo

# Animated demo runner
docker run -it aldeci-demo demo

# API server only (for external testing)
docker run -it -p 8000:8000 aldeci-demo api-only

# Then connect from another terminal
docker exec -it <container> /app/scripts/fixops-interactive.sh
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FIXOPS_API_URL` | `http://localhost:8000` | API server URL |
| `FIXOPS_API_TOKEN` | `demo-token-12345` | API authentication token |
| `FIXOPS_MODE` | `demo` | Operating mode (demo/enterprise) |
| `START_API_SERVER` | `true` | Whether to start API server |

## Sample Data

The scripts use sample data from `samples/api-examples/demo-scenarios/` which includes:
- 14 applications across different portfolios
- SAST/DAST/SCA/Container/Cloud scan results
- Micro-Pentest and Reachability analysis results
- Multi-LLM consensus decisions
- Evidence bundles with RSA-SHA256 signatures
- YAML playbooks with 25+ pre-approved actions
- Compliance assessments (PCI-DSS, SOC2, HIPAA, GDPR)

## Real-Time Data Generation

For generating fresh data at customer sites, see:
- `samples/api-examples/demo-scenarios/REALTIME-GENERATION.md`

## Requirements

**For direct script execution:**
- Bash 4.0+
- curl
- jq
- awk

**For Docker:**
- Docker 20.10+

## Troubleshooting

**Script not executable:**
```bash
chmod +x scripts/aldeci-demo-runner.sh scripts/fixops-interactive.sh
```

**API server not starting:**
- Check if port 8000 is available
- Verify Python dependencies are installed
- Check logs with `docker logs <container>`

**Animations not displaying correctly:**
- Ensure terminal supports 256 colors
- Set `TERM=xterm-256color`
- Use a modern terminal emulator
