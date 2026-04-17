# PRD: Community 528 — soc_triage_engine.SOCTriageEngine.get_instance

## Master Goal Mapping
**ALDECI Pillar**: SOC Operations — Triage Engine Singleton  
**Persona**: SOC Analyst (Tier 1)  
**Business Value**: Returns or creates the per-org SOC triage engine singleton, ensuring each organization's alert queue and triage rules are isolated and served from a single engine instance without per-request initialization overhead.

## Architecture Diagram
```mermaid
graph TD
    A[POST /api/v1/soc-workflow/triage] --> B[SOCTriageEngine.get_instance org_id]
    B --> C{_instances[org_id] exists?}
    C -->|yes| D[Return cached org engine]
    C -->|no| E[Create SOCTriageEngine for org_id]
    E --> F[Load triage rules from SQLite]
    F --> G[Cache _instances[org_id]]
    G --> D
    D --> H[triage_alert alert_dict]
    style B fill:#1a1a2e,color:#fff
```

## Code Proof
**File**: `suite-core/core/soc_triage_engine.py`  
```python
_instances: Dict[str, SOCTriageEngine] = {}
_instances_lock = threading.Lock()

@classmethod
def get_instance(cls, org_id: str) -> SOCTriageEngine:
    """Return (or create) the singleton engine for org_id."""
    if org_id not in _instances:
        with _instances_lock:
            if org_id not in _instances:
                _instances[org_id] = cls(org_id=org_id)
    return _instances[org_id]
```

## Inter-Dependencies
- **Upstream**: SOC workflow router, alert ingestion pipeline
- **Downstream**: `triage_alert`, `evaluate_rule_conditions` (Community 529)
- **Multi-tenant**: Each org_id has its own isolated engine and SQLite DB

## Data Flow
```
alert = {"severity": "critical", "source": "crowdstrike", "org_id": "acme-corp"}
  → SOCTriageEngine.get_instance("acme-corp")
    → _instances["acme-corp"] exists? → return cached
  → engine.triage_alert(alert)
```

## Referenced Docs
- `suite-core/core/soc_triage_engine.py`
- CLAUDE.md: SOC T1 Dashboard (/mission-control/soc-t1) — 1604 lines

## Acceptance Criteria
- [ ] Per-org isolation: org_A and org_B get different engine instances
- [ ] Thread-safe creation under concurrent requests from same org
- [ ] Engine cached after first creation (no re-init per request)
- [ ] `org_id` required — raises error if None/empty

## Effort Estimate
**XS** — 0.5 days. Pattern complete; multi-org isolation test needed.

## Status
**COMPLETE** — Implementation exists. Multi-org isolation test needed.
