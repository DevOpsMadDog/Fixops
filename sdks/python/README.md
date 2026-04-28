# aldeci-client

Typed Python client for the [ALDECI Security Intelligence Platform](https://github.com/DevOpsMadDog/Fixops) API.

Auto-generated from the live OpenAPI 3.1 spec (800+ endpoints). Provides async and sync HTTP clients with full Pydantic model coverage.

## Installation

```bash
pip install aldeci-client
```

## Quick Start

```python
from aldeci_client import AuthenticatedClient
from aldeci_client.api.issues import get_issues
from aldeci_client.models import IssueSeverity

# Initialize client
client = AuthenticatedClient(
    base_url="https://your-aldeci-instance.example.com",
    token="your-api-token",
)

# Sync usage
with client as c:
    issues = get_issues.sync(client=c)
    for issue in issues or []:
        print(issue.title, issue.severity)
```

## Async Usage

```python
import asyncio
from aldeci_client import AuthenticatedClient
from aldeci_client.api.issues import get_issues

async def main():
    async with AuthenticatedClient(
        base_url="https://your-aldeci-instance.example.com",
        token="your-api-token",
    ) as client:
        issues = await get_issues.asyncio(client=client)
        print(f"Found {len(issues or [])} issues")

asyncio.run(main())
```

## Unauthenticated Client

```python
from aldeci_client import Client

# For endpoints that do not require authentication
client = Client(base_url="http://localhost:8000")
```

## Advanced Customizations

Every path/method combination becomes a Python module with four functions:
- `sync`: Blocking request that returns parsed data (if successful) or `None`
- `sync_detailed`: Blocking request that always returns a `Response`, optionally with `parsed` set
- `asyncio`: Like `sync` but async
- `asyncio_detailed`: Like `sync_detailed` but async

Custom httpx hooks:

```python
from aldeci_client import Client

def log_request(request):
    print(f"{request.method} {request.url}")

client = Client(
    base_url="https://your-aldeci-instance.example.com",
    httpx_args={"event_hooks": {"request": [log_request]}},
)
```

SSL configuration:

```python
from aldeci_client import AuthenticatedClient

# Custom CA bundle
client = AuthenticatedClient(
    base_url="https://internal-aldeci.example.com",
    token="your-api-token",
    verify_ssl="/path/to/certificate_bundle.pem",
)

# Disable verification (not recommended for production)
client = AuthenticatedClient(
    base_url="https://internal-aldeci.example.com",
    token="your-api-token",
    verify_ssl=False,
)
```

## API Coverage

This client covers all 800+ ALDECI API endpoints including:

- **Issues** — vulnerability findings, severity triage, risk scoring
- **Assets** — inventory, SBOM, software composition analysis
- **Brain Pipeline** — AI analysis, LLM consensus, neural map
- **Connectors** — GitHub, GitLab, Jira, AWS, Azure, GCP integrations
- **Compliance** — SOC2, ISO27001, NIST, PCI-DSS, HIPAA frameworks
- **Threat Intelligence** — 28+ feed sources, CVE enrichment
- **Playbooks** — automated remediation workflows
- **Admin** — organizations, users, tokens, billing, MCP gateway

## Requirements

- Python 3.10+
- httpx >= 0.23.0
- attrs >= 22.2.0
- python-dateutil >= 2.8.0

## Publishing

```bash
# Build
poetry build

# Publish to PyPI
poetry publish --build
```

## License

MIT
