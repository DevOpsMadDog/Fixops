# PRD: Community 466 — scripts/export_openapi.py

## Master Goal Mapping
**ALDECI Pillar**: Developer Experience — OpenAPI Portal  
**Persona**: API Consumer, Integration Engineer  
**Business Value**: Exports the live OpenAPI 3.1 specification from the FastAPI app to a static JSON/YAML file, enabling Postman collection generation, SDK auto-generation, and the ALDECI developer portal (completed Wave 9: OpenAPI developer portal, 34 tests).

## Architecture Diagram
```mermaid
graph TD
    A[CI pipeline / Developer] --> B[export_openapi.py]
    B --> C[Import FastAPI app from suite-api/apps/app.py]
    C --> D[app.openapi() - generate spec]
    D --> E[Write openapi.json]
    D --> F[Write openapi.yaml]
    E & F --> G[suite-api/static/openapi.json]
    G --> H[OpenAPI Developer Portal /api/v1/openapi]
    G --> I[Postman collection import]
    G --> J[SDK auto-generation]
    style B fill:#457b9d,color:#fff
```

## Code Proof
**File**: `scripts/export_openapi.py`  
```python
from apps.app import app
import json, yaml
from pathlib import Path

spec = app.openapi()
Path("static/openapi.json").write_text(json.dumps(spec, indent=2))
Path("static/openapi.yaml").write_text(yaml.dump(spec))
print(f"Exported {len(spec['paths'])} endpoints")
```

## Inter-Dependencies
- **Upstream**: `suite-api/apps/app.py` — 34 router mounts, 850+ endpoints
- **Downstream**: `/api/v1/openapi` developer portal endpoint, Postman, SDK gen
- **Sibling**: `scripts/api_probe.py` (Community 467), `scripts/audit_apis.py` (Community 469)

## Data Flow
```
export_openapi.py
  → import FastAPI app
  → app.openapi() → full OpenAPI 3.1 spec dict
  → write static/openapi.json (850+ paths)
  → CI artifacts + deploy to /api/v1/openapi/spec endpoint
```

## Referenced Docs
- `scripts/export_openapi.py`
- CLAUDE.md DONE: "OpenAPI developer portal — 34 tests"
- FastAPI OpenAPI docs: https://fastapi.tiangolo.com/tutorial/metadata/

## Acceptance Criteria
- [ ] Exports valid OpenAPI 3.1 JSON
- [ ] All 34 router prefixes represented in spec
- [ ] Outputs both JSON and YAML formats
- [ ] Spec includes auth schemes (API key header)
- [ ] CI pipeline runs this on every merge to features/intermediate-stage

## Effort Estimate
**XS** — 0.5 days. Script exists; wire to CI pipeline.

## Status
**COMPLETE** — Script present. Wire to CI as post-merge artifact.
