# Security Triage Domain

## Purpose & User-Facing Screens

The Security Triage domain is the core of FixOps, providing security teams with tools to view, prioritize, and manage security vulnerabilities. It includes three main screens:

1. **Triage** (`/triage`) - Main vulnerability triage dashboard
2. **Findings** (`/findings`) - Individual finding detail view
3. **Risk Graph** (`/risk-graph`) - Interactive vulnerability relationship graph

## Key Files

### Frontend (MFE Apps)

| File | Role | Key Functions |
|------|------|---------------|
| `web/apps/triage/app/page.tsx` | Main triage page | Renders issue table, filters, bulk actions |
| `web/apps/triage/app/layout.tsx` | Layout wrapper | Wraps page with AppShell |
| `web/apps/triage/app/globals.css` | Global styles | Dark theme variables |
| `web/apps/findings/app/page.tsx` | Finding detail page | Shows CVE details, CVSS, remediation |
| `web/apps/risk-graph/app/page.tsx` | Graph visualization | Cytoscape.js graph rendering |

### Shared UI Components

| File | Role | Key Exports |
|------|------|-------------|
| `web/packages/ui/src/components/AppShell.tsx` | Main shell | `AppShell`, sidebar navigation |
| `web/packages/ui/src/components/StatusBadge.tsx` | Status indicators | `StatusBadge` |
| `web/packages/ui/src/components/Switch.tsx` | Toggle switch | `Switch` |

### API Client Hooks

| File | Hook | API Endpoint |
|------|------|--------------|
| `web/packages/api-client/src/hooks.ts` | `useTriage()` | `GET /api/v1/triage` |
| `web/packages/api-client/src/hooks.ts` | `useTriageExport()` | `POST /api/v1/triage/export` |
| `web/packages/api-client/src/hooks.ts` | `useFindingDetail(id)` | `GET /api/v1/findings/{id}` |
| `web/packages/api-client/src/hooks.ts` | `useGraph()` | `GET /api/v1/graph` |

### Backend API

| File | Role | Endpoints |
|------|------|-----------|
| `apps/api/app.py` | Main app | `GET /api/v1/triage`, `POST /api/v1/triage/export`, `GET /api/v1/graph` |
| `backend/api/graph/router.py` | Graph router | Graph generation endpoints |
| `backend/api/risk/router.py` | Risk router | Risk scoring endpoints |

### Core Modules

| File | Role | Key Functions |
|------|------|---------------|
| `core/cli.py` | CLI commands | `_handle_run()`, `_handle_analyze()` |
| `apps/api/pipeline.py` | Pipeline orchestrator | `PipelineOrchestrator.run()` |
| `apps/api/normalizers.py` | Input normalizers | `InputNormalizer`, `NormalizedSBOM`, `NormalizedSARIF` |
| `core/enhanced_decision.py` | Decision engine | `EnhancedDecisionEngine` |

## Public API Endpoints

### GET /api/v1/triage
Returns triaged security issues from the last pipeline run.

**Request:**
```bash
curl -H "X-API-Key: demo-token" http://127.0.0.1:8000/api/v1/triage
```

**Response:**
```json
{
  "rows": [
    {
      "id": "issue-001",
      "severity": "critical",
      "title": "SQL Injection in login handler",
      "source": "sarif",
      "repo": "backend-api",
      "location": "src/auth/login.py:42",
      "exploitability": {
        "kev": true,
        "epss": 0.85
      },
      "age_days": 14,
      "internet_facing": true,
      "description": "...",
      "remediation": "...",
      "evidence_bundle": {
        "id": "bundle-001",
        "signature_algorithm": "ECDSA-P256",
        "sha256": "..."
      },
      "decision": {
        "verdict": "immediate",
        "confidence": 0.92,
        "ssvc_outcome": "immediate",
        "rationale": "..."
      },
      "compliance_mappings": [
        {"framework": "SOC2", "control": "CC6.1"}
      ]
    }
  ],
  "summary": {
    "total": 156,
    "new_7d": 23,
    "high_critical": 45,
    "exploitable": 12,
    "internet_facing": 34
  }
}
```

### POST /api/v1/triage/export
Exports triage data to CSV or JSON format.

**Request:**
```bash
curl -X POST -H "X-API-Key: demo-token" \
  -H "Content-Type: application/json" \
  -d '{"format": "csv"}' \
  http://127.0.0.1:8000/api/v1/triage/export
```

### GET /api/v1/graph
Returns risk graph nodes and edges for visualization.

**Response:**
```json
{
  "nodes": [
    {
      "id": "service-1",
      "type": "service",
      "label": "API Gateway",
      "criticality": "high",
      "internet_facing": true
    },
    {
      "id": "vuln-1",
      "type": "vulnerability",
      "label": "CVE-2024-1234",
      "severity": "critical",
      "kev": true,
      "epss": 0.85
    }
  ],
  "edges": [
    {
      "id": "edge-1",
      "source": "vuln-1",
      "target": "service-1",
      "type": "affects"
    }
  ],
  "summary": {
    "services": 12,
    "components": 45,
    "issues": 156,
    "kev_count": 3
  }
}
```

## CLI Entrypoints

### python -m core.cli run
Runs the full pipeline to generate triage data.

```bash
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --design samples/design.csv \
  --sbom samples/sbom.json \
  --sarif samples/scan.sarif \
  --cve samples/cve.json \
  --output out/pipeline.json
```

**Handler:** `core/cli.py:_handle_run()` -> `_build_pipeline_result()`

### python -m core.cli analyze
Analyzes security findings with flexible input requirements.

```bash
python -m core.cli analyze \
  --sarif samples/scan.sarif \
  --output out/analysis.json
```

**Handler:** `core/cli.py:_handle_analyze()`

## Program Flow (UI-Request)

### Triage Page Load
```
1. Browser navigates to /triage
   |
2. Next.js renders web/apps/triage/app/layout.tsx
   |
3. layout.tsx renders AppShell from @fixops/ui
   |
4. AppShell renders sidebar navigation + main content area
   |
5. Next.js renders web/apps/triage/app/page.tsx
   |
6. page.tsx calls useTriage() hook
   |
7. useTriage() calls useApi('/api/v1/triage')
   |
8. useApi() calls fetchApi() from api-client
   |
9. fetchApi() makes HTTP GET to backend
   |
10. apps/api/app.py:get_triage() handles request
    |
11. get_triage() reads app.state.last_pipeline_result
    |
12. Returns JSON response with rows and summary
    |
13. Hook updates state, triggers React re-render
    |
14. page.tsx renders DataTable with issues
```

### Risk Graph Visualization
```
1. Browser navigates to /risk-graph
   |
2. page.tsx calls useGraph() hook
   |
3. useGraph() fetches /api/v1/graph
   |
4. apps/api/app.py:get_graph() generates graph
   |
5. Reads SBOM components, SARIF findings
   |
6. Builds nodes (services, components, vulnerabilities)
   |
7. Builds edges (affects, depends_on, contains)
   |
8. Returns graph JSON
   |
9. page.tsx initializes Cytoscape.js with data
   |
10. User can zoom, pan, filter, click nodes
```

## Program Flow (Data-Production)

### Pipeline Execution
```
1. CLI: python -m core.cli run --sbom X --sarif Y --cve Z
   |
2. core/cli.py:main() parses arguments
   |
3. build_parser() creates argparse parser
   |
4. _handle_run() is called
   |
5. _build_pipeline_result() executes:
   |
   5a. prepare_overlay() loads config
   |
   5b. InputNormalizer() created
   |
   5c. _load_inputs() reads files:
       - _load_design() -> design CSV
       - normalizer.load_sbom() -> NormalizedSBOM
       - normalizer.load_sarif() -> NormalizedSARIF
       - normalizer.load_cve_feed() -> NormalizedCVEFeed
   |
   5d. PipelineOrchestrator() created
   |
   5e. orchestrator.run() executes pipeline:
       - Correlates CVEs with SBOM components
       - Calculates risk scores
       - Generates SSVC decisions
       - Creates evidence bundles
   |
6. Result stored in app.state.last_pipeline_result
   |
7. Evidence bundle written to data/evidence/bundles/
   |
8. JSON output written to --output file
```

## Data Model / Payload Shapes

### Issue (Triage Row)
```typescript
interface Issue {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  source: 'sarif' | 'sbom' | 'cve' | 'manual';
  repo: string;
  location: string;
  exploitability: {
    kev: boolean;      // In CISA KEV catalog
    epss: number;      // 0-1 probability score
  };
  age_days: number;
  internet_facing: boolean;
  description: string;
  remediation: string;
  evidence_bundle: {
    id: string;
    signature_algorithm: string;
    retention_days: number;
    retained_until: string;
    sha256: string;
  };
  decision: {
    verdict: 'immediate' | 'out_of_cycle' | 'scheduled' | 'defer';
    confidence: number;
    ssvc_outcome: string;
    rationale: string;
    signals: Record<string, unknown>;
  };
  compliance_mappings: Array<{
    framework: string;
    control: string;
    description: string;
  }>;
}
```

### Graph Node
```typescript
interface GraphNode {
  id: string;
  type: 'service' | 'component' | 'vulnerability' | 'finding';
  label: string;
  severity?: string;
  criticality?: string;
  exposure?: string;
  internet_facing?: boolean;
  has_pii?: boolean;
  kev?: boolean;
  epss?: number;
}
```

## State & Storage

| Data | Storage Location | Persistence |
|------|------------------|-------------|
| Pipeline results | `app.state.last_pipeline_result` | In-memory (lost on restart) |
| Evidence bundles | `data/evidence/bundles/` | Filesystem |
| Evidence manifests | `data/evidence/manifests/` | Filesystem |
| Archived artifacts | `data/archive/{mode}/` | Filesystem |
| Analytics metrics | `data/analytics/{mode}/` | Filesystem |

## Common Failure Modes / Debugging

### "No pipeline data" in UI
**Cause:** Pipeline hasn't been run yet, `app.state.last_pipeline_result` is None.
**Fix:** Run pipeline via CLI or upload artifacts and call `/pipeline/run`.

### "API error - using demo data"
**Cause:** Backend API not running or authentication failed.
**Fix:** 
1. Start backend: `uvicorn apps.api.app:create_app --factory --reload`
2. Check API token: `export FIXOPS_API_TOKEN="demo-token"`

### Graph shows no nodes
**Cause:** SBOM not uploaded or pipeline not run.
**Fix:** Upload SBOM via `/inputs/sbom` and run pipeline.

### Risk scores all zero
**Cause:** CVE feed not loaded or no matches found.
**Fix:** Upload CVE feed via `/inputs/cve` with matching CVE IDs.

## Extension Points

### Adding a new triage column
1. Update `Issue` interface in `web/apps/triage/app/page.tsx`
2. Add column definition to `COLUMN_DEFINITIONS` array
3. Add cell renderer in the table body
4. Update `useTriage()` response type in `hooks.ts`
5. Update `get_triage()` in `apps/api/app.py` to include new field

### Adding a new risk signal
1. Add signal calculation in `core/enhanced_decision.py`
2. Include signal in pipeline result
3. Update graph node properties if needed
4. Add UI display in triage/findings pages

### Adding a new graph node type
1. Define node type in `backend/api/graph/router.py`
2. Add node generation logic in graph builder
3. Update Cytoscape styles in `risk-graph/app/page.tsx`
4. Add node click handler for details panel
