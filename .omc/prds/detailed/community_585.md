# PRD — Community 585: Cloud Connector — `list_findings` Abstract Interface

## Master Goal Mapping
**ALDECI Pillar:** Multi-cloud connector abstraction — defines the `list_findings` contract that all cloud provider implementations (AWS, Azure, GCP, etc.) must fulfill, ensuring normalized data output regardless of cloud API differences.

## Architecture Diagram
```mermaid
graph LR
    A[CloudProvider ABC] -->|@abstractmethod| B[list_findings]
    B -->|AWSProvider| C[AWS Security Hub / EC2 / IAM]
    B -->|AzureProvider| D[Azure Defender / ARM]
    B -->|GCPProvider| E[GCP Security Command Center]
    C & D & E -->|normalized| F[List[CloudFinding]]
```

## Code Proof
**File:** `suite-core/core/cloud_connectors.py:L383`  
**Module:** `cloud_connectors.CloudProvider.list_findings`

```python
@abstractmethod
def list_findings(self, ...) -> List[CloudFinding]:
    """Return normalized security findings."""
```

## Inter-Dependencies
- `AWSProvider.list_findings()` — AWS implementation
- `AzureProvider.list_findings()` — Azure implementation
- `GCPProvider.list_findings()` — GCP implementation
- Cloud compliance engine — calls `list_findings` on active providers
- `/api/v1/cloud-native` router — aggregates across providers

## Data Flow
Abstract method defined on `CloudProvider` base class → each cloud provider implements → returns normalized `List[CloudFinding]` regardless of provider API.

## Referenced Docs
- ALDECI Rearchitecture v2 §Multi-Cloud Connectors
- AWS Security Hub ASFF format
- Azure Defender for Cloud API
- GCP Security Command Center API

## Acceptance Criteria
- [ ] All concrete subclasses implement `list_findings`
- [ ] Return type is always `List[CloudFinding]` (normalized)
- [ ] Provider-specific exceptions translated to ALDECI exceptions
- [ ] Rate limiting respected via `_rate_limiter`
- [ ] Org isolation enforced (account-scoped data only)

## Effort Estimate
M — 2 days per provider (abstract contract implemented; provider implementations need integration tests)

## Status
DONE — abstract method defined at L383; AWS/Azure/GCP stubs present
