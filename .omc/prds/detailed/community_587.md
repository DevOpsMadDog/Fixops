# PRD — Community 587: Cloud Connector — `validate_credentials` Abstract Interface

## Master Goal Mapping
**ALDECI Pillar:** Multi-cloud connector abstraction — defines the `validate_credentials` contract that all cloud provider implementations (AWS, Azure, GCP, etc.) must fulfill, ensuring normalized data output regardless of cloud API differences.

## Architecture Diagram
```mermaid
graph LR
    A[CloudProvider ABC] -->|@abstractmethod| B[validate_credentials]
    B -->|AWSProvider| C[AWS Security Hub / EC2 / IAM]
    B -->|AzureProvider| D[Azure Defender / ARM]
    B -->|GCPProvider| E[GCP Security Command Center]
    C & D & E -->|normalized| F[tuple[bool, str]]
```

## Code Proof
**File:** `suite-core/core/cloud_connectors.py:L391`  
**Module:** `cloud_connectors.CloudProvider.validate_credentials`

```python
@abstractmethod
def validate_credentials(self, ...) -> tuple[bool, str]:
    """Test connectivity and return (ok, message)."""
```

## Inter-Dependencies
- `AWSProvider.validate_credentials()` — AWS implementation
- `AzureProvider.validate_credentials()` — Azure implementation
- `GCPProvider.validate_credentials()` — GCP implementation
- Cloud compliance engine — calls `validate_credentials` on active providers
- `/api/v1/cloud-native` router — aggregates across providers

## Data Flow
Abstract method defined on `CloudProvider` base class → each cloud provider implements → returns normalized `tuple[bool, str]` regardless of provider API.

## Referenced Docs
- ALDECI Rearchitecture v2 §Multi-Cloud Connectors
- AWS Security Hub ASFF format
- Azure Defender for Cloud API
- GCP Security Command Center API

## Acceptance Criteria
- [ ] All concrete subclasses implement `validate_credentials`
- [ ] Return type is always `tuple[bool, str]` (normalized)
- [ ] Provider-specific exceptions translated to ALDECI exceptions
- [ ] Rate limiting respected via `_rate_limiter`
- [ ] Org isolation enforced (account-scoped data only)

## Effort Estimate
M — 2 days per provider (abstract contract implemented; provider implementations need integration tests)

## Status
DONE — abstract method defined at L391; AWS/Azure/GCP stubs present
