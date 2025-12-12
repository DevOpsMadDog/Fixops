# FixOps Docker Setup Instructions

This guide explains how to run FixOps locally using Docker.

## Prerequisites

- Docker installed and running
- Docker Hub account (optional, for pulling the pre-built image)

## Quick Start

### Option 1: Pull from Docker Hub (Recommended)

```bash
# Pull the latest image
docker pull devopsaico/fixops:latest

# Run the container
docker run -d \
  --name fixops \
  -p 8000:8000 \
  -e FIXOPS_API_TOKEN="your-api-token" \
  -e FIXOPS_DISABLE_TELEMETRY=1 \
  devopsaico/fixops:latest
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# Build the Docker image
docker build -t fixops:local .

# Run the container
docker run -d \
  --name fixops \
  -p 8000:8000 \
  -e FIXOPS_API_TOKEN="your-api-token" \
  -e FIXOPS_DISABLE_TELEMETRY=1 \
  fixops:local
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FIXOPS_API_TOKEN` | API authentication token | `demo-token` |
| `FIXOPS_DISABLE_TELEMETRY` | Disable OpenTelemetry metrics | `0` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OpenTelemetry collector endpoint | `http://collector:4318` |

### Volume Mounts (Optional)

Mount local directories for persistent data:

```bash
docker run -d \
  --name fixops \
  -p 8000:8000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/config:/app/config \
  -e FIXOPS_API_TOKEN="your-api-token" \
  devopsaico/fixops:latest
```

## Verifying the Installation

Once the container is running, verify it's working:

```bash
# Check container status
docker ps

# Check health endpoint
curl http://localhost:8000/health

# Check API documentation
open http://localhost:8000/docs
```

## API Usage Examples

### Upload Security Artifacts

```bash
# Set your API token
export FIXOPS_API_TOKEN="your-api-token"

# Upload design document
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/design.csv;type=text/csv" \
  http://localhost:8000/inputs/design

# Upload SBOM
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/sbom.json;type=application/json" \
  http://localhost:8000/inputs/sbom

# Upload CVE data
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/cve.json;type=application/json" \
  http://localhost:8000/inputs/cve

# Upload SARIF scan results
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@samples/scan.sarif;type=application/json" \
  http://localhost:8000/inputs/sarif
```

### Run the Pipeline

```bash
# Execute the security pipeline
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/pipeline/run | jq

# Get enhanced capabilities
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/api/v1/enhanced/capabilities | jq
```

### Compare LLM Providers

```bash
curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -X POST \
  -H 'Content-Type: application/json' \
  -d '{
    "service_name": "demo-app",
    "security_findings": [
      {"rule_id": "SAST001", "severity": "high", "description": "SQL injection"}
    ],
    "business_context": {
      "environment": "demo",
      "criticality": "high"
    }
  }' \
  http://localhost:8000/api/v1/enhanced/compare-llms | jq
```

## Docker Compose (Optional)

For a more complete setup with additional services:

```yaml
version: '3.8'

services:
  fixops:
    image: devopsaico/fixops:latest
    ports:
      - "8000:8000"
    environment:
      - FIXOPS_API_TOKEN=your-api-token
      - FIXOPS_DISABLE_TELEMETRY=1
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

Save as `docker-compose.yml` and run:

```bash
docker-compose up -d
```

## Stopping the Container

```bash
# Stop the container
docker stop fixops

# Remove the container
docker rm fixops
```

## Troubleshooting

### Container won't start

Check the logs:
```bash
docker logs fixops
```

### Port already in use

Use a different port:
```bash
docker run -d --name fixops -p 9000:8000 devopsaico/fixops:latest
```

### Permission issues with volumes

Ensure the mounted directories have correct permissions:
```bash
chmod -R 755 ./data ./config
```

## Image Details

- **Base Image**: python:3.11-slim
- **Size**: ~1.6GB (optimized with multi-stage build)
- **PyTorch**: CPU-only version (reduces size from 15GB)
- **Exposed Port**: 8000

## Support

For issues or questions, please open an issue on GitHub:
https://github.com/DevOpsMadDog/Fixops/issues
