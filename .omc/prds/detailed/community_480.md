# PRD: Community 480 — trustgraph_schemas.get_schema

## Master Goal Mapping
**ALDECI Pillar**: TrustGraph Knowledge Graph — Schema Management  
**Persona**: Platform Engineer, Integration Engineer  
**Business Value**: Get schema for a Knowledge Core by core_id (1-5). Returns entity types, relationship types, and property definitions for the specified Knowledge Core.

## Architecture Diagram
```mermaid
graph TD
    A[Connector / API] --> B[trustgraph_schemas.get_schema]
    B --> C[Knowledge Core schemas: Core1-5]
    C --> D[Core 1: Customer Environment - assets, findings]
    C --> E[Core 2: Threat Intelligence - CVEs, attackers]
    C --> F[Core 3: Compliance - frameworks, controls]
    C --> G[Core 4: Decision Memory - verdicts, triage]
    C --> H[Core 5: Competitive Intelligence]
    B --> I[Return schema/validation result]
    style B fill:#6d4c41,color:#fff
```

## Code Proof
**File**: `suite-core/connectors/trustgraph_schemas.py`  
Function: `get_schema`

The five Knowledge Cores are defined as Pydantic models:
- `Organization`, `Team`, `Service`, `Repository`, `Artifact`, `Container`, `CloudAccount`, `Endpoint` (Core 1)
- CVE, ThreatActor, Exploit (Core 2)
- Framework, Control, Evidence (Core 3)
- TriageDecision, RemediationAction (Core 4)
- Competitor, Product (Core 5)

## Inter-Dependencies
- **Upstream**: `suite-core/connectors/universal_connector.py` (calls schema validation)
- **Downstream**: TrustGraph MCP server, GraphRAG retriever
- **Models**: Pydantic v2 `BaseModel` classes with `ConfigDict(json_schema_extra={"core": N})`

## Data Flow
```
connector.ingest_finding(finding)
  → route_finding_to_cores(finding) → [core_id=2, core_id=3]
  → for each core_id: validate_entity(entity, core_id)
    → get_schema(core_id) → schema dict
    → check required fields, type constraints
  → if valid: push to TrustGraph MCP
```

## Referenced Docs
- `suite-core/connectors/trustgraph_schemas.py`
- TrustGraph documentation: https://trustgraph.ai
- CLAUDE.md DONE: "TrustGraph GraphRAG retriever — 31 tests"

## Acceptance Criteria
- [ ] `get_schema` returns correct data for all 5 core IDs
- [ ] Invalid core_id raises `ValueError` with clear message
- [ ] Schema definitions match Pydantic model fields
- [ ] Used by connector health check endpoint
- [ ] Thread-safe (schemas are read-only constants)

## Effort Estimate
**XS** — 0.5 days. Implementation complete; unit tests for all 5 cores.

## Status
**COMPLETE** — Schema functions implemented. Unit tests for edge cases needed.
