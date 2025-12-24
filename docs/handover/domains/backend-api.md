# Backend API Architecture

## Overview

The FixOps backend is a FastAPI application that provides REST API endpoints for security data ingestion, pipeline execution, and data retrieval. The API supports both token-based and JWT authentication strategies.

## Key Files

### Main Application

| File | Role | Key Functions |
|------|------|---------------|
| `apps/api/app.py` | Main FastAPI app factory | `create_app()`, route handlers |
| `apps/api/pipeline.py` | Pipeline orchestrator | `PipelineOrchestrator.run()` |
| `apps/api/normalizers.py` | Input data normalizers | `InputNormalizer`, `NormalizedSBOM`, `NormalizedSARIF` |
| `apps/api/middleware.py` | Request middleware | `CorrelationIdMiddleware`, `RequestLoggingMiddleware` |
| `apps/api/upload_manager.py` | Chunked uploads | `ChunkUploadManager` |

### API Routers (22 files)

| Router File | Prefix | Endpoints | Purpose |
|-------------|--------|-----------|---------|
| `analytics_router.py` | `/api/v1/analytics` | 16 | Dashboard, metrics, ROI |
| `inventory_router.py` | `/api/v1/inventory` | 15 | Application/service inventory |
| `pentagi_router_enhanced.py` | `/api/v1/pentagi` | 14 | AI penetration testing |
| `marketplace_router.py` | `/api/v1/marketplace` | 12 | Security tool marketplace |
| `reports_router.py` | `/api/v1/reports` | 10 | Report generation |
| `audit_router.py` | `/api/v1/audit` | 10 | Audit logging |
| `teams_router.py` | `/api/v1/teams` | 8 | Team management |
| `policies_router.py` | `/api/v1/policies` | 8 | Policy management |
| `integrations_router.py` | `/api/v1/integrations` | 8 | Third-party integrations |
| `workflows_router.py` | `/api/v1/workflows` | 7 | Workflow automation |
| `users_router.py` | `/api/v1/users` | 6 | User management |
| `secrets_router.py` | `/api/v1/secrets` | 5 | Secret detection |
| `iac_router.py` | `/api/v1/iac` | 5 | IaC scanning |
| `bulk_router.py` | `/api/v1/bulk` | 5 | Bulk operations |
| `auth_router.py` | `/api/v1/auth` | 4 | Authentication/SSO |
| `ide_router.py` | `/api/v1/ide` | 3 | IDE plugin integration |
| `health_router.py` | `/health` | 1 | Health check |

### Backend API Modules

| File | Role | Key Functions |
|------|------|---------------|
| `backend/api/evidence/router.py` | Evidence bundles | 3 endpoints |
| `backend/api/graph/router.py` | Risk graph | 4 endpoints |
| `backend/api/risk/router.py` | Risk scoring | 3 endpoints |
| `backend/api/provenance/router.py` | Artifact provenance | 2 endpoints |

## Authentication

### Token-Based Authentication
```python
# Header: X-API-Key: <token>
# Validated against overlay.auth_tokens tuple
```

### JWT Authentication
```python
# Header: Authorization: Bearer <token>
# Decoded with JWT_SECRET, expires in JWT_EXP_MINUTES (default 120)
```

### Configuration
```yaml
# config/fixops.overlay.yml
auth:
  strategy: token  # or "jwt"
  header: X-API-Key  # or "Authorization" for JWT
```

## Entry Points

### Application Factory
```python
# apps/api/app.py
def create_app() -> FastAPI:
    """Create and configure FastAPI application."""
    overlay = load_overlay(allow_demo_token_fallback=True)
    flag_provider = create_flag_provider(overlay.raw_config)
    
    app = FastAPI(
        title=f"{branding['product_name']} Ingestion Demo API",
        description=f"Security decision engine by {branding['org_name']}",
        version="0.1.0",
    )
    
    # Add middleware
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(CORSMiddleware, ...)
    
    # Include routers
    app.include_router(health_router)
    app.include_router(evidence_router, dependencies=[Depends(_verify_api_key)])
    app.include_router(graph_router, dependencies=[Depends(_verify_api_key)])
    # ... more routers
    
    return app
```

### Running the API
```bash
export FIXOPS_API_TOKEN="demo-token"
uvicorn apps.api.app:create_app --factory --reload
```

## Core Endpoints

### Health Check
```
GET /health
GET /api/v1/health/ready
```

### Data Ingestion
```
POST /inputs/design    - Upload design CSV
POST /inputs/sbom      - Upload SBOM (CycloneDX, SPDX, Syft)
POST /inputs/sarif     - Upload SARIF scan results
POST /inputs/cve       - Upload CVE feed
POST /inputs/vex       - Upload VEX document
POST /inputs/cnapp     - Upload CNAPP data
POST /inputs/context   - Upload business context
```

### Chunked Upload
```
POST /uploads/init           - Initialize upload session
POST /uploads/{session}/chunk - Upload chunk
POST /uploads/{session}/complete - Complete upload
GET  /uploads/{session}/status - Check upload status
```

### Pipeline Execution
```
POST /pipeline/run - Execute full pipeline
```

### Triage & Graph
```
GET  /api/v1/triage        - Get triaged issues
POST /api/v1/triage/export - Export triage data
GET  /api/v1/graph         - Get risk graph
```

### Enhanced Decision
```
GET  /api/v1/enhanced/capabilities - Get LLM capabilities
POST /api/v1/enhanced/compare-llms - Compare LLM decisions
```

## Data Flow

### Ingestion Flow
```
1. Client uploads file via POST /inputs/{stage}
   |
2. _read_limited() streams file with size limit
   |
3. _validate_content_type() checks MIME type
   |
4. _process_{stage}() normalizes data:
   - _process_sbom() -> NormalizedSBOM
   - _process_sarif() -> NormalizedSARIF
   - _process_cve() -> NormalizedCVEFeed
   |
5. _store() persists to app.state.artifacts
   |
6. archive.persist() saves to data/archive/{mode}/
```

### Pipeline Flow
```
1. POST /pipeline/run
   |
2. PipelineOrchestrator.run() executes:
   |
   2a. Load artifacts from app.state.artifacts
   |
   2b. Correlate CVEs with SBOM components
   |
   2c. Calculate risk scores
   |
   2d. Generate SSVC decisions
   |
   2e. Create evidence bundles
   |
3. Store result in app.state.last_pipeline_result
   |
4. Return JSON response
```

## State Management

### Application State
```python
app.state.normalizer = InputNormalizer()
app.state.orchestrator = PipelineOrchestrator()
app.state.artifacts = {}  # Uploaded artifacts
app.state.overlay = overlay  # Configuration
app.state.archive = ArtefactArchive(archive_dir)
app.state.archive_records = {}
app.state.analytics_store = AnalyticsStore(analytics_dir)
app.state.last_pipeline_result = None  # Pipeline output
app.state.feedback = FeedbackRecorder(overlay)
app.state.enhanced_engine = EnhancedDecisionEngine(settings)
app.state.upload_manager = ChunkUploadManager(uploads_dir)
```

### Storage Directories
```
data/
├── archive/{mode}/      # Persisted artifacts
├── analytics/{mode}/    # Metrics and forecasts
├── evidence/
│   ├── manifests/       # Evidence manifests
│   └── bundles/         # Evidence archives
├── artifacts/
│   ├── attestations/    # Provenance attestations
│   └── sbom/            # SBOM files
├── analysis/            # Graph data
├── uploads/{mode}/      # Chunked upload sessions
├── pentagi.db           # Pentagi SQLite DB
├── policies.db          # Policies SQLite DB
└── reports.db           # Reports SQLite DB
```

## Router Details

### Analytics Router (`analytics_router.py`)
```python
GET  /api/v1/analytics/dashboard/overview
GET  /api/v1/analytics/dashboard/trends
GET  /api/v1/analytics/dashboard/top-risks
GET  /api/v1/analytics/dashboard/compliance-status
GET  /api/v1/analytics/metrics
GET  /api/v1/analytics/roi
GET  /api/v1/analytics/mttr
GET  /api/v1/analytics/coverage
GET  /api/v1/analytics/noise-reduction
GET  /api/v1/analytics/recommendations
GET  /api/v1/analytics/anomalies
GET  /api/v1/analytics/user-activity
GET  /api/v1/analytics/policy-changes
GET  /api/v1/analytics/signals
GET  /api/v1/analytics/monitoring
POST /api/v1/analytics/custom-query
```

### Pentagi Router (`pentagi_router_enhanced.py`)
```python
GET  /api/v1/pentagi/requests
POST /api/v1/pentagi/requests
GET  /api/v1/pentagi/requests/{request_id}
POST /api/v1/pentagi/requests/{request_id}/start
POST /api/v1/pentagi/requests/{request_id}/cancel
GET  /api/v1/pentagi/results
GET  /api/v1/pentagi/results/by-request/{request_id}
GET  /api/v1/pentagi/stats
GET  /api/v1/pentagi/configs
POST /api/v1/pentagi/configs
GET  /api/v1/pentagi/configs/{config_id}
PUT  /api/v1/pentagi/configs/{config_id}
DELETE /api/v1/pentagi/configs/{config_id}
GET  /api/v1/pentagi/findings/{finding_id}/exploitability
```

### Reports Router (`reports_router.py`)
```python
GET  /api/v1/reports
POST /api/v1/reports
GET  /api/v1/reports/{id}
GET  /api/v1/reports/{id}/download
DELETE /api/v1/reports/{id}
GET  /api/v1/reports/schedules/list
POST /api/v1/reports/schedule
GET  /api/v1/reports/templates/list
POST /api/v1/reports/export/csv
POST /api/v1/reports/export/sarif
```

## Error Handling

### HTTP Status Codes
```
200 - Success
201 - Created
400 - Bad Request (validation error)
401 - Unauthorized (missing/invalid token)
403 - Forbidden (insufficient permissions)
404 - Not Found
413 - Payload Too Large (upload limit exceeded)
422 - Unprocessable Entity (validation error)
500 - Internal Server Error
```

### Error Response Format
```json
{
  "detail": "Error message",
  "status_code": 400,
  "error_type": "ValidationError"
}
```

## Testing

### Test Files
```
tests/test_reports_api.py
tests/test_pentagi_api.py
tests/test_policies_api.py
tests/test_end_to_end.py
```

### Running Tests
```bash
pytest tests/test_reports_api.py -v
pytest tests/test_pentagi_api.py -v
```

## Extension Points

### Adding a New Router
1. Create `apps/api/{domain}_router.py`
2. Define router: `router = APIRouter(prefix="/api/v1/{domain}", tags=["{domain}"])`
3. Add endpoints with `@router.get()`, `@router.post()`, etc.
4. Import and include in `apps/api/app.py`:
   ```python
   from apps.api.{domain}_router import router as {domain}_router
   app.include_router({domain}_router, dependencies=[Depends(_verify_api_key)])
   ```

### Adding a New Endpoint
1. Define handler function in appropriate router
2. Add request/response models if needed
3. Add authentication dependency if required
4. Add to OpenAPI documentation with docstring

### Adding Middleware
1. Create middleware class in `apps/api/middleware.py`
2. Add to app in `create_app()`:
   ```python
   app.add_middleware(MyMiddleware)
   ```
