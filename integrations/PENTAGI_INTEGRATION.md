# Advanced Pentagi Integration with FixOps

This document describes the enhanced integration between Pentagi (AI-powered penetration testing) and FixOps (security decision engine).

## Overview

The integration provides advanced automated penetration testing capabilities similar to:
- **Akido Security**: Automated vulnerability verification and exploitability testing
- **Prism Security**: Continuous security monitoring and scanning

## Architecture

```
┌─────────────────┐
│   FixOps API   │
│   (FastAPI)    │
└────────┬────────┘
         │
         ├───► Pentagi Router (Enhanced)
         │         │
         │         ├───► Advanced Pentagi Service
         │         │         │
         │         │         ├───► Pentagi Client
         │         │         │         │
         │         │         │         └───► Pentagi Instance
         │         │         │                  (Go Backend)
         │         │         │
         │         │         └───► Pentagi Database
         │         │
         │         └───► Decision Integration
         │                   │
         │                   └───► Enhanced Decision Engine
         │
         └───► FixOps Decision Engine
```

## Features

### 1. Automated Vulnerability Verification

Automatically verify vulnerabilities by attempting exploitation, similar to Akido Security's approach.

**Endpoint**: `POST /api/v1/pentagi/verify`

```json
{
  "finding_id": "finding-123",
  "target_url": "https://example.com/api",
  "vulnerability_type": "SQL Injection",
  "evidence": "Parameter 'id' is vulnerable to SQL injection"
}
```

**Response**:
```json
{
  "verified": true,
  "exploitable": true,
  "findings": [
    {
      "id": "finding-123",
      "title": "SQL Injection in /api/users",
      "severity": "critical",
      "exploit_successful": true,
      "evidence": "..."
    }
  ]
}
```

### 2. Continuous Security Monitoring

Set up continuous monitoring for multiple targets with configurable scan intervals.

**Endpoint**: `POST /api/v1/pentagi/monitoring`

```json
{
  "targets": [
    "https://api.example.com",
    "https://app.example.com"
  ],
  "interval_minutes": 60
}
```

### 3. Comprehensive Multi-Vector Scanning

Run comprehensive security scans across multiple attack vectors in parallel.

**Endpoint**: `POST /api/v1/pentagi/scan/comprehensive`

```json
{
  "target": "https://example.com",
  "scan_types": [
    "web_application",
    "api_security",
    "network_scan",
    "code_analysis"
  ]
}
```

### 4. Integration with Decision Engine

Pen test results are automatically integrated into FixOps decision-making:

- **Exploitability Assessment**: Findings are classified as:
  - `confirmed_exploitable`: Exploitation confirmed
  - `likely_exploitable`: High probability of exploitation
  - `inconclusive`: Unable to determine
  - `unexploitable`: Not exploitable
  - `blocked`: Blocked by security controls

- **Risk Adjustment**: Decision scores are adjusted based on exploitability
- **Action Enhancement**: Recommended actions are enhanced with exploitability context

**Endpoint**: `GET /api/v1/pentagi/findings/{finding_id}/exploitability`

## Configuration

### 1. Create Pentagi Configuration

```bash
POST /api/v1/pentagi/configs
```

```json
{
  "name": "Production Pentagi",
  "pentagi_url": "https://pentagi.example.com",
  "api_key": "your-api-key",
  "enabled": true,
  "max_concurrent_tests": 5,
  "timeout_seconds": 300,
  "auto_trigger": true,
  "target_environments": ["production", "staging"]
}
```

### 2. Auto-Trigger Configuration

When `auto_trigger` is enabled, pen tests are automatically triggered for:
- Critical/High severity findings
- Internet-facing medium severity findings
- CVE findings with high EPSS scores

## Usage Examples

### Example 1: Verify a SQL Injection Finding

```python
import httpx

async with httpx.AsyncClient() as client:
    response = await client.post(
        "https://fixops.example.com/api/v1/pentagi/verify",
        json={
            "finding_id": "sql-injection-001",
            "target_url": "https://api.example.com/users",
            "vulnerability_type": "SQL Injection",
            "evidence": "User input in 'id' parameter is not sanitized"
        },
        headers={"Authorization": "Bearer YOUR_TOKEN"}
    )
    result = response.json()
    print(f"Exploitable: {result['exploitable']}")
```

### Example 2: Set Up Continuous Monitoring

```python
import httpx

async with httpx.AsyncClient() as client:
    response = await client.post(
        "https://fixops.example.com/api/v1/pentagi/monitoring",
        json={
            "targets": [
                "https://api.example.com",
                "https://app.example.com"
            ],
            "interval_minutes": 60
        },
        headers={"Authorization": "Bearer YOUR_TOKEN"}
    )
    jobs = response.json()
    print(f"Monitoring jobs: {jobs['jobs']}")
```

### Example 3: Get Exploitability for Decision Making

```python
import httpx

async with httpx.AsyncClient() as client:
    response = await client.get(
        "https://fixops.example.com/api/v1/pentagi/findings/finding-123/exploitability",
        headers={"Authorization": "Bearer YOUR_TOKEN"}
    )
    exploitability = response.json()
    
    if exploitability['exploitability'] == 'confirmed_exploitable':
        # Take immediate action
        print("CRITICAL: Vulnerability is confirmed exploitable!")
```

## Integration with FixOps Decision Engine

The `PentagiDecisionIntegration` class enhances FixOps decision results with exploitability data:

```python
from integrations.pentagi_decision_integration import PentagiDecisionIntegration
from core.enhanced_decision import MultiLLMResult

integration = PentagiDecisionIntegration(pentagi_service, db)

# Enhance decision with exploitability
enhanced_result = integration.enhance_decision_with_exploitability(
    decision_result=llm_result,
    finding_id="finding-123"
)

# Check if pen test should be triggered
should_test = integration.should_trigger_pen_test(
    finding_severity="critical",
    finding_source="SAST",
    internet_facing=True
)
```

## Statistics and Monitoring

Get statistics about pen tests:

**Endpoint**: `GET /api/v1/pentagi/stats`

```json
{
  "total_requests": 150,
  "total_results": 142,
  "by_status": {
    "completed": 120,
    "running": 15,
    "pending": 10,
    "failed": 5
  },
  "by_exploitability": {
    "confirmed_exploitable": 25,
    "likely_exploitable": 30,
    "unexploitable": 50,
    "inconclusive": 20,
    "blocked": 17
  },
  "by_priority": {
    "critical": 40,
    "high": 60,
    "medium": 35,
    "low": 15
  }
}
```

## Advanced Features

### 1. Test Type Mapping

Vulnerability types are automatically mapped to appropriate Pentagi test types:

- SQL Injection, XSS, CSRF → `web_application`
- API vulnerabilities → `api_security`
- Network issues → `network_scan`
- Code issues → `code_analysis`
- Cloud issues → `cloud_security`
- Container issues → `container_security`

### 2. Evidence Formatting

Evidence is automatically formatted from pen test findings:
- Primary finding details
- Severity and CVSS scores
- CWE/CVE references
- Attack vectors
- Additional findings summary

### 3. Artifact Extraction

Artifacts are automatically extracted from test results:
- Screenshots
- Payloads
- Log files
- Network captures

## Error Handling

The integration includes robust error handling:

- **Service Unavailable**: Falls back to basic request creation if Pentagi service is not configured
- **Test Timeout**: Tests are automatically cancelled after timeout
- **Retry Logic**: HTTP requests include retry logic with exponential backoff
- **Graceful Degradation**: System continues to function even if Pentagi is unavailable

## Security Considerations

1. **API Keys**: Store API keys securely, never in code
2. **Network Isolation**: Pentagi tests run in isolated Docker containers
3. **Rate Limiting**: Respect Pentagi instance rate limits
4. **Data Privacy**: Pen test results may contain sensitive information
5. **Authorization**: Ensure proper authorization before triggering tests

## Troubleshooting

### Service Not Available

If you see "Pentagi service not configured":
1. Create a configuration via `/api/v1/pentagi/configs`
2. Ensure `enabled` is set to `true`
3. Verify `pentagi_url` is correct
4. Check API key is valid

### Tests Not Completing

1. Check Pentagi instance is running
2. Verify network connectivity
3. Check timeout settings
4. Review Pentagi logs

### Low Confidence Scores

1. Ensure test configuration is appropriate
2. Verify target is accessible
3. Check test type matches vulnerability
4. Review evidence quality

## Future Enhancements

Planned improvements:
- [ ] Integration with CI/CD pipelines
- [ ] Webhook notifications for test completion
- [ ] Advanced reporting and dashboards
- [ ] Machine learning for false positive reduction
- [ ] Integration with ticketing systems
- [ ] Compliance mapping (OWASP, CWE, etc.)

## References

- [Pentagi Documentation](https://github.com/vxcontrol/pentagi)
- [FixOps Documentation](./README.md)
- [Akido Security](https://akido.com)
- [Prism Security](https://prism.com)
