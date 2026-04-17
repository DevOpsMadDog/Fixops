# PRD — Community 584: Cloud Connector — `get_resource` Abstract Interface

## Master Goal Mapping
**ALDECI Pillar:** Multi-cloud connector abstraction — defines the `get_resource` contract that all cloud provider implementations (AWS, Azure, GCP, etc.) must fulfill, ensuring normalized data output regardless of cloud API differences.

## Architecture Diagram
```mermaid
graph LR
    A[CloudProvider ABC] -->|@abstractmethod| B[get_resource]
    B -->|AWSProvider| C[AWS Security Hub / EC2 / IAM]
    B -->|AzureProvider| D[Azure Defender / ARM]
    B -->|GCPProvider| E[GCP Security Command Center]
    C & D & E -->|normalized| F[Optional[CloudResource]]
```

## Code Proof
**File:** `suite-core/core/cloud_connectors.py:L379`  
**Module:** `cloud_connectors.CloudProvider.get_resource`

```python
@abstractmethod
def get_resource(self, ...) -> Optional[CloudResource]:
    """Return a single normalized resource by ID."""
```

## Inter-Dependencies
- `AWSProvider.get_resource()` — AWS implementation
- `AzureProvider.get_resource()` — Azure implementation
- `GCPProvider.get_resource()` — GCP implementation
- Cloud compliance engine — calls `get_resource` on active providers
- `/api/v1/cloud-native` router — aggregates across providers

## Data Flow
Abstract method defined on `CloudProvider` base class → each cloud provider implements → returns normalized `Optional[CloudResource]` regardless of provider API.

## Referenced Docs
- ALDECI Rearchitecture v2 §Multi-Cloud Connectors
- AWS Security Hub ASFF format
- Azure Defender for Cloud API
- GCP Security Command Center API

## Acceptance Criteria
- [ ] All concrete subclasses implement `get_resource`
- [ ] Return type is always `Optional[CloudResource]` (normalized)
- [ ] Provider-specific exceptions translated to ALDECI exceptions
- [ ] Rate limiting respected via `_rate_limiter`
- [ ] Org isolation enforced (account-scoped data only)

## Effort Estimate
M — 2 days per provider (abstract contract implemented; provider implementations need integration tests)

## Status
DONE — abstract method defined at L379; AWS/Azure/GCP stubs present
