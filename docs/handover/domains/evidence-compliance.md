# Evidence & Compliance Domain

## Purpose & User-Facing Screens

The Evidence & Compliance domain provides tools for generating audit-ready evidence bundles and managing compliance frameworks. It includes:

1. **Evidence** (`/evidence`) - Evidence bundle management and download
2. **Compliance** (`/compliance`) - Compliance framework tracking and gap analysis
3. **Policies** (`/policies`) - Security policy management
4. **Audit** (`/audit`) - Audit log viewer

## Key Files

### Frontend (MFE Apps)

| File | Role | Key Functions |
|------|------|---------------|
| `web/apps/evidence/app/page.tsx` | Evidence list page | Lists bundles, download actions |
| `web/apps/compliance/app/page.tsx` | Compliance dashboard | Framework progress, gap analysis |
| `web/apps/policies/app/page.tsx` | Policy management | Policy CRUD (demo only) |
| `web/apps/audit/app/page.tsx` | Audit log viewer | Log filtering, export (demo only) |

### API Client Hooks

| File | Hook | API Endpoint | Status |
|------|------|--------------|--------|
| `hooks.ts` | `useEvidence()` | `GET /api/v1/evidence` | Integrated |
| `hooks.ts` | `useCompliance()` | `GET /api/v1/compliance/summary` | Integrated |
| `hooks.ts` | `usePolicies()` | `GET /api/v1/policies` | Hook exists, NOT wired to UI |
| `hooks.ts` | `useAuditLogs()` | `GET /api/v1/audit` | Hook exists, NOT wired to UI |

### Backend API

| File | Role | Endpoints |
|------|------|-----------|
| `backend/api/evidence/router.py` | Evidence router | 3 endpoints |
| `apps/api/policies_router.py` | Policies router | 8 endpoints |
| `apps/api/audit_router.py` | Audit router | 10 endpoints |

### Core Modules

| File | Role | Key Functions |
|------|------|---------------|
| `core/evidence.py` | Evidence generation | `EvidenceHub`, bundle creation |
| `core/compliance.py` | Compliance logic | Framework mappings |
| `core/policy.py` | Policy engine | Policy evaluation |
| `core/policy_db.py` | Policy storage | CRUD operations |
| `core/policy_models.py` | Policy models | Data structures |
| `core/audit_db.py` | Audit storage | Log persistence |
| `core/audit_models.py` | Audit models | Log entry structure |

## Public API Endpoints

### Evidence Endpoints

#### GET /api/v1/evidence
Lists all evidence bundles.

**Response:**
```json
{
  "items": [
    {
      "id": "bundle-001",
      "timestamp": "2024-01-15T10:30:00Z",
      "issue_id": "issue-001",
      "issue_title": "SQL Injection in login handler",
      "severity": "critical",
      "decision": {
        "verdict": "immediate",
        "confidence": 0.92,
        "outcome": "remediate"
      },
      "signature": {
        "algorithm": "ECDSA-P256",
        "public_key_id": "key-001",
        "signature_hex": "..."
      },
      "retention": {
        "mode": "compliance",
        "days": 365,
        "retained_until": "2025-01-15T10:30:00Z"
      },
      "checksum": {
        "algorithm": "SHA-256",
        "value": "abc123..."
      },
      "size_bytes": 4096
    }
  ],
  "total": 156,
  "limit": 100,
  "offset": 0
}
```

#### GET /api/v1/evidence/{id}/download
Downloads an evidence bundle archive.

### Compliance Endpoints

#### GET /api/v1/compliance/summary
Returns compliance framework summary and gaps.

**Response:**
```json
{
  "frameworks": [
    {
      "id": "soc2",
      "name": "SOC 2 Type II",
      "description": "Service Organization Control 2",
      "controls_total": 64,
      "controls_passed": 58,
      "controls_failed": 4,
      "controls_not_applicable": 2,
      "last_assessed": "2024-01-15T10:30:00Z"
    }
  ],
  "overall_score": 0.91,
  "gaps": [
    {
      "control_id": "CC6.1",
      "framework": "SOC2",
      "description": "Logical access security",
      "severity": "high",
      "remediation": "Implement MFA for all users"
    }
  ]
}
```

#### GET /api/v1/compliance/frameworks
Lists all compliance frameworks.

#### GET /api/v1/compliance/frameworks/{id}/gaps
Returns gaps for a specific framework.

### Policy Endpoints

#### GET /api/v1/policies
Lists all security policies.

**Response:**
```json
{
  "items": [
    {
      "id": "policy-001",
      "name": "Critical Vulnerability SLA",
      "description": "Critical vulnerabilities must be remediated within 7 days",
      "type": "sla",
      "status": "active",
      "last_evaluated": "2024-01-15T10:30:00Z",
      "created_at": "2024-01-01T00:00:00Z"
    }
  ],
  "total": 12,
  "limit": 100,
  "offset": 0
}
```

#### POST /api/v1/policies
Creates a new policy.

#### PUT /api/v1/policies/{id}
Updates an existing policy.

#### DELETE /api/v1/policies/{id}
Deletes a policy.

### Audit Endpoints

#### GET /api/v1/audit
Lists audit log entries.

**Response:**
```json
{
  "items": [
    {
      "id": "log-001",
      "action": "finding.status_changed",
      "user_id": "user-001",
      "user_email": "admin@example.com",
      "resource_type": "finding",
      "resource_id": "finding-001",
      "details": {
        "old_status": "open",
        "new_status": "resolved"
      },
      "ip_address": "192.168.1.1",
      "timestamp": "2024-01-15T10:30:00Z"
    }
  ],
  "total": 1500,
  "limit": 100,
  "offset": 0
}
```

## CLI Entrypoints

### python -m core.cli get-evidence
Retrieves evidence bundles from a pipeline run.

```bash
python -m core.cli get-evidence \
  --run out/pipeline.json \
  --output out/evidence/
```

**Handler:** `core/cli.py:_handle_get_evidence()`

### python -m core.cli copy-evidence
Copies evidence bundles to a target directory.

```bash
python -m core.cli copy-evidence \
  --run out/pipeline.json \
  --target ./hand-off/
```

### python -m core.cli compliance list
Lists compliance frameworks and their status.

```bash
python -m core.cli compliance list
```

**Handler:** `core/cli.py:_handle_compliance()`

### python -m core.cli compliance assess
Runs compliance assessment against a framework.

```bash
python -m core.cli compliance assess --framework soc2
```

### python -m core.cli policies list
Lists all security policies.

```bash
python -m core.cli policies list
```

**Handler:** `core/cli.py:_handle_policies()`

### python -m core.cli audit list
Lists audit log entries.

```bash
python -m core.cli audit list --limit 100
```

**Handler:** `core/cli.py:_handle_audit()`

## Program Flow (UI-Request)

### Evidence Page Load
```
1. Browser navigates to /evidence
   |
2. page.tsx calls useEvidence() hook
   |
3. useEvidence() calls useApi('/api/v1/evidence')
   |
4. HTTP GET to backend
   |
5. backend/api/evidence/router.py handles request
   |
6. Reads evidence bundles from evidence_bundle_dir
   |
7. Returns JSON with bundle metadata
   |
8. UI renders bundle list with download buttons
```

### Evidence Bundle Download
```
1. User clicks "Download" button
   |
2. page.tsx calls download function
   |
3. HTTP GET /api/v1/evidence/{id}/download
   |
4. Backend reads bundle file from filesystem
   |
5. Returns binary file with Content-Disposition header
   |
6. Browser downloads .zip archive
```

### Compliance Dashboard Load
```
1. Browser navigates to /compliance
   |
2. page.tsx calls useCompliance() hook
   |
3. useCompliance() calls useApi('/api/v1/compliance/summary')
   |
4. HTTP GET to backend
   |
5. apps/api/app.py:_get_compliance_mappings() generates data
   |
6. Maps findings to compliance controls
   |
7. Calculates pass/fail counts per framework
   |
8. Returns JSON with frameworks and gaps
   |
9. UI renders framework cards and gap table
```

## Program Flow (Data-Production)

### Evidence Bundle Generation
```
1. Pipeline runs via CLI or API
   |
2. PipelineOrchestrator.run() executes
   |
3. For each finding, creates evidence record:
   |
   3a. core/evidence.py:EvidenceHub.generate_bundle()
   |
   3b. Collects finding details, decision, signals
   |
   3c. Creates JSON manifest
   |
   3d. Signs manifest with configured key
   |
   3e. Creates .zip archive with:
       - manifest.json
       - finding_details.json
       - decision_record.json
       - signature.sig
   |
4. Writes bundle to data/evidence/bundles/{bundle_id}.zip
   |
5. Writes manifest to data/evidence/manifests/{bundle_id}.json
   |
6. Returns bundle metadata in pipeline result
```

## Data Model / Payload Shapes

### Evidence Bundle
```typescript
interface EvidenceBundle {
  id: string;
  timestamp: string;
  issue_id: string;
  issue_title: string;
  severity: string;
  decision: {
    verdict: string;
    confidence: number;
    outcome: string;
  };
  signature: {
    algorithm: string;
    public_key_id: string;
    signature_hex: string;
  };
  retention: {
    mode: string;
    days: number;
    retained_until: string;
  };
  checksum: {
    algorithm: string;
    value: string;
  };
  size_bytes: number;
}
```

### Compliance Framework
```typescript
interface ComplianceFramework {
  id: string;
  name: string;
  description: string;
  controls_total: number;
  controls_passed: number;
  controls_failed: number;
  controls_not_applicable: number;
  last_assessed: string;
}
```

### Policy
```typescript
interface Policy {
  id: string;
  name: string;
  description: string;
  type: 'sla' | 'gate' | 'notification' | 'automation';
  status: 'active' | 'inactive' | 'draft';
  rules: Array<{
    condition: string;
    action: string;
  }>;
  last_evaluated: string;
  created_at: string;
}
```

### Audit Log Entry
```typescript
interface AuditLogEntry {
  id: string;
  action: string;
  user_id: string;
  user_email: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown>;
  ip_address: string;
  timestamp: string;
}
```

## State & Storage

| Data | Storage Location | Persistence |
|------|------------------|-------------|
| Evidence bundles | `data/evidence/bundles/` | Filesystem |
| Evidence manifests | `data/evidence/manifests/` | Filesystem |
| Policies | `core/policy_db.py` | In-memory (demo) |
| Audit logs | `core/audit_db.py` | In-memory (demo) |
| Compliance mappings | Generated from pipeline | In-memory |

## Common Failure Modes / Debugging

### "No evidence bundles found"
**Cause:** Pipeline hasn't been run or evidence generation disabled.
**Fix:** Run pipeline with evidence generation enabled in overlay.

### Evidence signature verification fails
**Cause:** Signing key not configured or key mismatch.
**Fix:** Configure `SIGNING_PROVIDER` and `KEY_ID` environment variables.

### Compliance gaps not showing
**Cause:** No compliance mappings in pipeline result.
**Fix:** Ensure findings have `compliance_mappings` field populated.

### Policies/Audit showing demo data
**Cause:** UI not wired to API hooks.
**Fix:** Replace `useState` with `usePolicies()` / `useAuditLogs()` hooks.

## Extension Points

### Adding a new compliance framework
1. Add framework definition in `core/compliance.py`
2. Define control mappings (finding rule -> control)
3. Update `_get_compliance_mappings()` in `apps/api/app.py`
4. Add framework card in compliance UI

### Adding a new policy type
1. Define policy type in `core/policy_models.py`
2. Add evaluation logic in `core/policy.py`
3. Update `policies_router.py` to handle new type
4. Add UI form for new policy type

### Adding custom audit events
1. Define event type in `core/audit_models.py`
2. Add logging call in relevant code path
3. Update `audit_router.py` if new filters needed
4. Add event display in audit UI

## Integration Status

| Screen | API Integration | Notes |
|--------|-----------------|-------|
| Evidence | Fully integrated | `useEvidence()` hook wired |
| Compliance | Fully integrated | `useCompliance()` hook wired |
| Policies | NOT integrated | Hook exists but UI uses demo data |
| Audit | NOT integrated | Hook exists but UI uses demo data |

### To Complete Integration

**Policies page (`web/apps/policies/app/page.tsx`):**
```typescript
// Replace:
const [policies, setPolicies] = useState(DEMO_POLICIES);

// With:
import { usePolicies } from '@fixops/api-client';
const { data, loading, error } = usePolicies();
const policies = data?.items || [];
```

**Audit page (`web/apps/audit/app/page.tsx`):**
```typescript
// Replace:
const [logs, setLogs] = useState(DEMO_LOGS);

// With:
import { useAuditLogs } from '@fixops/api-client';
const { data, loading, error } = useAuditLogs();
const logs = data?.items || [];
```
