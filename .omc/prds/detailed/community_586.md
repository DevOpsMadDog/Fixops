# PRD — Community 586: Cloud Connector — `get_posture` Abstract Interface

## Master Goal Mapping
**ALDECI Pillar:** Multi-cloud connector abstraction — defines the `get_posture` contract that all cloud provider implementations (AWS, Azure, GCP, etc.) must fulfill, ensuring normalized data output regardless of cloud API differences.

## Architecture Diagram
```mermaid
graph LR
    A[CloudProvider ABC] -->|@abstractmethod| B[get_posture]
    B -->|AWSProvider| C[AWS Security Hub / EC2 / IAM]
    B -->|AzureProvider| D[Azure Defender / ARM]
    B -->|GCPProvider| E[GCP Security Command Center]
    C & D & E -->|normalized| F[PostureReport]
```

## Code Proof
**File:** `suite-core/core/cloud_connectors.py:L387`  
**Module:** `cloud_connectors.CloudProvider.get_posture`

```python
@abstractmethod
def get_posture(self, ...) -> PostureReport:
    """Return security posture summary for this account."""
```

## Inter-Dependencies
- `AWSProvider.get_posture()` — AWS implementation
- `AzureProvider.get_posture()` — Azure implementation
- `GCPProvider.get_posture()` — GCP implementation
- Cloud compliance engine — calls `get_posture` on active providers
- `/api/v1/cloud-native` router — aggregates across providers

## Data Flow
Abstract method defined on `CloudProvider` base class → each cloud provider implements → returns normalized `PostureReport` regardless of provider API.

## Referenced Docs
- ALDECI Rearchitecture v2 §Multi-Cloud Connectors
- AWS Security Hub ASFF format
- Azure Defender for Cloud API
- GCP Security Command Center API

## Acceptance Criteria
- [ ] All concrete subclasses implement `get_posture`
- [ ] Return type is always `PostureReport` (normalized)
- [ ] Provider-specific exceptions translated to ALDECI exceptions
- [ ] Rate limiting respected via `_rate_limiter`
- [ ] Org isolation enforced (account-scoped data only)

## Effort Estimate
M — 2 days per provider (abstract contract implemented; provider implementations need integration tests)

## Status
DONE — abstract method defined at L387; AWS/Azure/GCP stubs present
