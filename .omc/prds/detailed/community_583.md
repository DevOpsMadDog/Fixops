# PRD — Community 583: Cloud Connector — `list_resources` Abstract Interface

## Master Goal Mapping
**ALDECI Pillar:** Multi-cloud connector abstraction — defines the `list_resources` contract that all cloud provider implementations (AWS, Azure, GCP, etc.) must fulfill, ensuring normalized data output regardless of cloud API differences.

## Architecture Diagram
```mermaid
graph LR
    A[CloudProvider ABC] -->|@abstractmethod| B[list_resources]
    B -->|AWSProvider| C[AWS Security Hub / EC2 / IAM]
    B -->|AzureProvider| D[Azure Defender / ARM]
    B -->|GCPProvider| E[GCP Security Command Center]
    C & D & E -->|normalized| F[List[CloudResource]]
```

## Code Proof
**File:** `suite-core/core/cloud_connectors.py:L375`  
**Module:** `cloud_connectors.CloudProvider.list_resources`

```python
@abstractmethod
def list_resources(self, ...) -> List[CloudResource]:
    """Return normalized resources from this account."""
```

## Inter-Dependencies
- `AWSProvider.list_resources()` — AWS implementation
- `AzureProvider.list_resources()` — Azure implementation
- `GCPProvider.list_resources()` — GCP implementation
- Cloud compliance engine — calls `list_resources` on active providers
- `/api/v1/cloud-native` router — aggregates across providers

## Data Flow
Abstract method defined on `CloudProvider` base class → each cloud provider implements → returns normalized `List[CloudResource]` regardless of provider API.

## Referenced Docs
- ALDECI Rearchitecture v2 §Multi-Cloud Connectors
- AWS Security Hub ASFF format
- Azure Defender for Cloud API
- GCP Security Command Center API

## Acceptance Criteria
- [ ] All concrete subclasses implement `list_resources`
- [ ] Return type is always `List[CloudResource]` (normalized)
- [ ] Provider-specific exceptions translated to ALDECI exceptions
- [ ] Rate limiting respected via `_rate_limiter`
- [ ] Org isolation enforced (account-scoped data only)

## Effort Estimate
M — 2 days per provider (abstract contract implemented; provider implementations need integration tests)

## Status
DONE — abstract method defined at L375; AWS/Azure/GCP stubs present
