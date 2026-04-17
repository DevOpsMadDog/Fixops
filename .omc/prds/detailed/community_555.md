# PRD — Community 555: API Doc Generator — camelCase OperationId Deriver

## Master Goal Mapping
**ALDECI Pillar:** OpenAPI developer portal — derives deterministic, snake_case `operationId` strings from HTTP method + path, ensuring every endpoint has a unique, SDK-friendly identifier.

## Architecture Diagram
```mermaid
graph LR
    A[EndpointDoc method+path] --> B[_make_operation_id]
    B -->|split path segments| C[parts list]
    B -->|{param} → by_param| D[param segment rewrite]
    C & D -->|join + normalize| E[operationId string]
    E --> F[OpenAPI spec operationId field]
```

## Code Proof
**File:** `suite-core/core/api_doc_generator.py:L524`  
**Module:** `api_doc_generator.APIDocGenerator._make_operation_id`

```python
@staticmethod
def _make_operation_id(ep: EndpointDoc) -> str:
    """Derive a camelCase operationId from method + path."""
    parts = [ep.method.lower()]
    for segment in ep.path.split("/"):
        if not segment: continue
        if segment.startswith("{") and segment.endswith("}"):
            parts.append("by_" + segment[1:-1])
        else:
            parts.append(segment)
    return "_".join(parts).replace("-", "_")
```

## Inter-Dependencies
- `_parse_router_file()` — produces `EndpointDoc` objects passed to this method
- `generate_openapi_spec()` — uses operationId for each path item
- C554 `_build_tag_groups` — sibling helper in same class

## Data Flow
Method + path → segment split → path param rewrite → underscore join → hyphen normalization → operationId string.

## Referenced Docs
- ALDECI Rearchitecture v2 §OpenAPI Developer Portal
- OpenAPI 3.1 spec §operationId
- SDK generation tools (openapi-generator) requirements

## Acceptance Criteria
- [ ] `GET /api/v1/findings/{id}` → `get_api_v1_findings_by_id`
- [ ] `POST /api/v1/alerts` → `post_api_v1_alerts`
- [ ] Hyphens in path segments replaced by underscores
- [ ] Empty path segments skipped
- [ ] All operationIds unique across spec

## Effort Estimate
S — 1 day (implemented; add parameterized path tests)

## Status
DONE — implemented at L524
