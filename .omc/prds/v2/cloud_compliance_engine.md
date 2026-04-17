# US-0050: Cloud Compliance

## Sub-Epic: CSPM
**Master Goal**: ALDECI — $35/mo enterprise security intelligence platform replacing $50K-500K/yr tools

## User Story
As a **Jennifer Wu (Cloud Security Architect)**, I need to secure cloud infrastructure and workloads
so that the platform delivers enterprise-grade cspm capabilities at 1/1000th the cost of legacy tools.

## Why This Matters
Cloud Compliance replaces functionality found in enterprise tools like CrowdStrike, Wiz, Snyk, and Rapid7.
By building this into ALDECI's $35/mo stack, customers save $50K+/yr on standalone CSPM tooling.

## Architecture
```mermaid
graph TD
    Client["Frontend Dashboard"] -->|HTTP| API["/api/v1/cloud-compliance"]
    API --> Auth["api_key_auth"]
    Auth --> Router["cloud_compliance_router.py"]
    Router --> Engine["CloudComplianceEngine"]
    Engine --> DB[(SQLite: {org_id}_cloud_compliance.db)]
    Engine --> Lock["threading.RLock"]
    Engine -->|emit| EventBus["TrustGraph EventBus"]
    EventBus --> Subscribers["CrossCategorySubscribers"]
    CloudComplianceEngine --> Dep0["trustgraph_event_bus"]
    Subscribers --> AlertEngine["AlertTriageEngine"]
    Subscribers --> RiskEngine["RiskAggregatorEngine"]
```

## Current State: 95% Complete
- ✅ `create_assessment()` — Create a new compliance assessment. (line 171)
- ✅ `list_assessments()` — List assessments, optionally filtered. (line 224)
- ✅ `get_assessment()` — Return assessment with a control summary. (line 249)
- ✅ `add_control_result()` — Record a control result and update the assessment score. (line 279)
- ✅ `complete_assessment()` — Mark assessment completed, compute final score, detect drift. (line 354)
- ✅ `list_control_results()` — List control results with optional filters. (line 439)
- ❌ TrustGraph event emission — not yet verified

## Key Functions (from `suite-core/core/cloud_compliance_engine.py` — 646 lines)
- `CloudComplianceEngine.create_assessment()` — Create a new compliance assessment. (line 171)
- `CloudComplianceEngine.list_assessments()` — List assessments, optionally filtered. (line 224)
- `CloudComplianceEngine.get_assessment()` — Return assessment with a control summary. (line 249)
- `CloudComplianceEngine.add_control_result()` — Record a control result and update the assessment score. (line 279)
- `CloudComplianceEngine.complete_assessment()` — Mark assessment completed, compute final score, detect drift. (line 354)
- `CloudComplianceEngine.list_control_results()` — List control results with optional filters. (line 439)
- `CloudComplianceEngine.create_remediation_plan()` — Create a remediation plan. (line 466)
- `CloudComplianceEngine.update_remediation_plan()` — Update remediation plan status. Returns True if found. (line 509)

## Dependencies
- **Depends on**: trustgraph_event_bus
- **Depended by**: Routers, TrustGraph EventBus, CrossCategorySubscribers
- **TrustGraph**: Event emission wired via ResponseInterceptorMiddleware
- **Source file**: `suite-core/core/cloud_compliance_engine.py` (646 lines)
- **Router file**: `suite-api/apps/api/cloud_compliance_router.py`

## API Endpoints
| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/cloud-compliance/assessments` | create assessment |
| GET | `/api/v1/cloud-compliance/assessments` | list assessments |
| GET | `/api/v1/cloud-compliance/assessments/{assessment_id}` | get assessment |
| POST | `/api/v1/cloud-compliance/assessments/{assessment_id}/controls` | add control result |
| POST | `/api/v1/cloud-compliance/assessments/{assessment_id}/complete` | complete assessment |
| GET | `/api/v1/cloud-compliance/controls` | list control results |
| POST | `/api/v1/cloud-compliance/remediation-plans` | create remediation plan |
| PATCH | `/api/v1/cloud-compliance/remediation-plans/{plan_id}/status` | update remediation plan |
| GET | `/api/v1/cloud-compliance/remediation-plans` | list remediation plans |
| GET | `/api/v1/cloud-compliance/drift` | list drift history |
| GET | `/api/v1/cloud-compliance/stats` | get compliance stats |

## Tasks Remaining
1. Verify TrustGraph event emission works end-to-end (2h)
2. Add integration test with real persona workflow (2h)
3. Wire CrossCategorySubscriber consumer chain (1h)
4. Validate with 30-persona walkthrough (1h)
5. Optimize query performance for large datasets (2h)
6. Expand test coverage to edge cases (2h)

## Definition of Done
- [ ] Jennifer Wu (Cloud Security Architect) can access /api/v1/cloud-compliance and get meaningful data
- [ ] All CRUD operations return correct HTTP status codes
- [ ] TrustGraph receives events from this engine
- [ ] 37+ tests passing in `tests/test_cloud_compliance_engine.py`
- [ ] 30-persona walkthrough includes this endpoint at 100%
- [ ] No hardcoded org_id — all queries are org-scoped

## Sprint: Wave 43 (est. April 19-21, 2026)

## Test Coverage
- **Test file**: `tests/test_cloud_compliance_engine.py`
- **Tests**: 37 tests
- **Status**: Passing
