# Quick Start Guide: PentAGI + FixOps Integration

## Overview

This guide will help you quickly set up and use the enhanced PentAGI with FixOps integration.

## Prerequisites

- Docker and Docker Compose
- PentAGI instance running
- FixOps instance running
- API keys configured

## Setup Steps

### 1. Configure PentAGI

Add FixOps configuration to your PentAGI `.env` file:

```bash
# FixOps Integration
FIXOPS_BASE_URL=http://fixops:8000
FIXOPS_API_KEY=your_fixops_api_key_here
```

### 2. Configure FixOps

Ensure FixOps has the API key configured:

```bash
FIXOPS_API_KEY=your_fixops_api_key_here
```

### 3. Restart Services

```bash
# Restart PentAGI
cd pentagi
docker compose restart pentagi

# Restart FixOps
cd fixops-enterprise
# Follow FixOps restart instructions
```

## Using the New Features

### Continuous Scanning

Start a continuous scan through the PentAGI UI or API:

```bash
curl -X POST https://pentagi:8443/api/v1/flows \
  -H "Content-Type: application/json" \
  -d '{
    "input": "Start continuous scan of https://example.com",
    "provider": "openai"
  }'
```

The AI agent will automatically use the `continuous_scanner` tool.

### Risk Assessment

When vulnerabilities are found, the `risk_scorer` tool automatically calculates risk scores. You can also manually trigger risk assessment:

```bash
# Through PentAGI assistant
"Assess the risk of the SQL injection vulnerability found at /api/users"
```

### FixOps Integration

Findings are automatically submitted to FixOps when using the `fixops_integration` tool. You can also manually submit:

```bash
# Through PentAGI assistant
"Submit the penetration test findings to FixOps for analysis"
```

## Verification

### Check PentAGI Health

```bash
curl https://pentagi:8443/api/v1/info
```

### Check FixOps Health

```bash
curl https://fixops:8000/api/v1/pentagi/health
```

### Test Integration

```bash
curl -X POST https://fixops:8000/api/v1/pentagi/findings \
  -H "Authorization: Bearer your_fixops_api_key" \
  -H "Content-Type: application/json" \
  -d '{
    "findings": [
      {
        "id": "test-001",
        "title": "Test Vulnerability",
        "severity": "medium",
        "type": "xss",
        "location": "/test"
      }
    ]
  }'
```

## Example Workflow

1. **Start Pentest**: Create a new flow in PentAGI targeting your application
2. **Automated Scanning**: PentAGI performs comprehensive security testing
3. **Risk Assessment**: Each finding is automatically scored for risk
4. **FixOps Analysis**: Findings are submitted to FixOps for enhanced analysis
5. **Remediation**: Review FixOps recommendations and remediate vulnerabilities

## Troubleshooting

### FixOps Integration Not Working

1. Verify `FIXOPS_BASE_URL` is correct
2. Check `FIXOPS_API_KEY` matches FixOps configuration
3. Ensure network connectivity between PentAGI and FixOps
4. Check FixOps logs for errors

### Tools Not Available

1. Verify tools are registered in `registry.go`
2. Check tool availability in executor configuration
3. Review PentAGI logs for initialization errors

### API Errors

1. Verify API keys are correct
2. Check CORS configuration
3. Review authentication headers
4. Check API endpoint URLs

## Next Steps

- Read [INTEGRATION.md](pentagi/INTEGRATION.md) for detailed integration guide
- Read [ADVANCED_FEATURES.md](pentagi/ADVANCED_FEATURES.md) for feature documentation
- Review [PENTAGI_IMPROVEMENTS_SUMMARY.md](PENTAGI_IMPROVEMENTS_SUMMARY.md) for complete overview
