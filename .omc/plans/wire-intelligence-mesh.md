# Plan: Wire ALDECI Intelligence Mesh

## Requirements Summary
Connect 250+ wave engines to the intelligence layer (brain pipeline, TrustGraph, ML models, event bus). Currently 95% of engines are isolated CRUD islands. Goal: transform ALDECI from disconnected databases into a correlated security intelligence platform.

## Acceptance Criteria
1. TrustGraph event bus intercepts 54+ entity key types (up from 6)
2. Top 20 wave engines emit events on state change via event bus
3. 3 ML models wired to their corresponding wave engines
4. Persona dashboards query real engine data (0 hardcoded values)
5. GraphRAG returns real KnowledgeStore queries (not mock data)
6. 716/716 Beast Mode tests pass (zero regressions)
7. Re-run 308-prefix coverage test shows >30% data-populated (up from 16%)

## Implementation Steps

### Step 1: Extend TrustGraph Event Bus Key Map (HIGH PRIORITY, LOW EFFORT)
**File:** `suite-core/core/trustgraph_event_bus.py:89-97`

Add 48 new entity key patterns to `_RESPONSE_KEY_MAP`. Currently matches 6 keys. Need to add all 54 unique entity ID fields from wave engines.

New entries (grouped by domain):
```python
# Vulnerability Management
"ticket_id": (EVENT_FINDING_CREATED, "vuln_ticket"),
"scan_id": (EVENT_SCAN_COMPLETED, "scan"),
"cve_id": (EVENT_CVE_DISCOVERED, "cve"),
"detection_id": (EVENT_THREAT_DETECTED, "detection"),

# Risk & Compliance
"risk_id": (EVENT_RISK_ASSESSED, "risk"),
"assessment_id": (EVENT_CONTROL_ASSESSED, "assessment"),
"gap_id": (EVENT_CONTROL_ASSESSED, "gap"),
"policy_id": (EVENT_POLICY_UPDATED, "policy"),
"framework_id": (EVENT_CONTROL_ASSESSED, "framework"),
"evidence_id": (EVENT_EVIDENCE_COLLECTED, "evidence"),

# Identity & Access
"identity_id": (EVENT_IDENTITY_UPDATED, "identity"),
"session_id": (EVENT_SESSION_CREATED, "session"),
"device_id": (EVENT_ASSET_DISCOVERED, "device"),

# Threat Intel
"campaign_id": (EVENT_THREAT_DETECTED, "campaign"),
"technique_id": (EVENT_THREAT_DETECTED, "technique"),

# Incidents & Alerts
"alert_id": (EVENT_ALERT_CREATED, "alert"),
"rule_id": (EVENT_RULE_UPDATED, "rule"),
"execution_id": (EVENT_PLAYBOOK_EXECUTED, "execution"),

... (all 48 remaining)
```

Also need to add missing EVENT_* constants if they don't exist in the event type definitions.

**Verification:** After change, POST to any wave engine → check TrustGraph KnowledgeStore has new node.

### Step 2: Wire Event Bus into Top 20 Wave Engines (HIGH PRIORITY, MEDIUM EFFORT)
**5-10 lines per engine.** Add `_emit_event()` calls on state-changing methods (create, update, delete).

Target engines (by importance):
1. `edr_engine.py` — emit THREAT_DETECTED on register_detection()
2. `ndr_engine.py` — emit THREAT_DETECTED on create_alert()
3. `behavioral_analytics_engine.py` — emit ANOMALY_DETECTED on detect_anomaly()
4. `ransomware_protection_engine.py` — emit THREAT_DETECTED on register_detection()
5. `incident_orchestration_engine.py` — emit INCIDENT_CREATED on create_incident()
6. `alert_triage_engine.py` — emit ALERT_CREATED on create_alert()
7. `vuln_workflow_engine.py` — emit FINDING_CREATED on create_ticket()
8. `access_anomaly_engine.py` — emit ANOMALY_DETECTED on record_event()
9. `threat_correlation_engine.py` — emit THREAT_DETECTED on create_correlation()
10. `identity_risk_engine.py` — emit IDENTITY_UPDATED on create_identity()
11. `insider_threat_engine.py` — emit THREAT_DETECTED on analyze_user_risk()
12. `dark_web_monitoring_engine.py` — emit THREAT_DETECTED on create_mention()
13. `cloud_posture_engine.py` — emit CONTROL_ASSESSED on create_account()
14. `kubernetes_security_engine.py` — emit ASSET_DISCOVERED on register_cluster()
15. `supply_chain_attack_detection_engine.py` — emit THREAT_DETECTED on register_detection()
16. `privacy_impact_assessment_engine.py` — emit CONTROL_ASSESSED on create_assessment()
17. `zero_day_intelligence_engine.py` — emit CVE_DISCOVERED on register_vulnerability()
18. `ai_powered_soc_engine.py` — emit FINDING_CREATED on register_detection()
19. `risk_register_engine.py` — emit RISK_ASSESSED on create_risk()
20. `compliance_mapping_engine.py` — emit CONTROL_ASSESSED on add_control()

**Pattern for each engine (add to __init__ and state-change methods):**
```python
# At top of file
try:
    from core.trustgraph_event_bus import get_event_bus
    _event_bus = get_event_bus()
except ImportError:
    _event_bus = None

# In state-change method (e.g., register_detection)
def register_detection(self, org_id, ...):
    # existing CRUD logic
    result = ...
    # NEW: emit event
    if _event_bus:
        _event_bus.emit("THREAT_DETECTED", {
            "entity_type": "detection",
            "entity_id": result["id"],
            "org_id": org_id,
            "source_engine": "edr",
        })
    return result
```

**Verification:** Create detection in EDR → verify TrustGraph node count increases.

### Step 3: Wire ML Models to Wave Engines (MEDIUM PRIORITY, LOW EFFORT)
**3 connections to make.**

a. `risk_scorer` → `vuln_prioritization_engine.py`
   - File: `suite-core/core/vulnerability_prioritization_engine.py`
   - In `add_vulnerability()`, after inserting, call `risk_scorer.predict()` to compute ML-based priority
   - ML model: `suite-core/core/ml/risk_scorer.py`

b. `anomaly_detector` → `behavioral_analytics_engine.py`
   - File: `suite-core/core/behavioral_analytics_engine.py`
   - In `detect_anomaly()`, call `anomaly_detector.detect()` instead of `min(count * 10, 100)`
   - ML model: `suite-core/core/ml/anomaly_detector.py`

c. `attack_path_gnn` → `attack_path_engine.py`
   - File: `suite-core/core/attack_path_engine.py`
   - In `analyze()`, optionally use GNN embeddings for path scoring
   - ML model: `suite-core/core/ml/attack_path_gnn.py`

**Pattern:**
```python
try:
    from core.ml.risk_scorer import RiskScorer
    _scorer = RiskScorer()
except ImportError:
    _scorer = None

def add_vulnerability(self, ...):
    # existing CRUD
    if _scorer:
        features = {"cvss": cvss_score, "epss": epss_score, "kev": in_kev}
        priority = _scorer.predict(features)
        # update the record with ML-computed priority
```

**Verification:** Add vuln → verify priority is ML-computed (not just severity string).

### Step 4: Replace Persona Dashboard Hardcoded Values (MEDIUM PRIORITY, MEDIUM EFFORT)
**File:** `suite-core/core/analytics_engine.py:479-805`

Replace hardcoded values in `PersonaDashboard` methods with real queries:

a. `get_ciso_dashboard()` — query:
   - `risk_score` from risk_register_engine stats
   - `critical_count/high_count` from brain pipeline findings
   - `compliance` from compliance engine status
   - `kpi.sla_compliance_percent` from kpi_tracking_engine

b. `get_devsecops_dashboard()` — query:
   - `scans_last_day` from scanner_ingest stats
   - `builds_blocked` from devsecops engine stats
   - `sast_findings` from findings store

c. Similar for all 30 persona methods.

**Pattern:**
```python
def get_ciso_dashboard(self, org_id):
    # Query real engines instead of hardcoded values
    try:
        from core.risk_register_engine import RiskRegisterEngine
        risk_eng = RiskRegisterEngine()
        risk_stats = risk_eng.get_stats(org_id)
        risk_score = risk_stats.get("avg_risk_score", 0)
    except Exception:
        risk_score = 0
    ...
```

**Verification:** CISO dashboard returns different values based on actual org data.

### Step 5: Fix GraphRAG Stub (MEDIUM PRIORITY, MEDIUM EFFORT)
**File:** `suite-core/core/graphrag_engine.py:270-320`

Replace `_retrieve_from_single_core()` mock data with real KnowledgeStore queries.

```python
# Before (mock):
results = [{"type": entity, "score": 0.8} for entity in mock_entities]

# After (real):
from trustgraph.knowledge_store import KnowledgeStore
store = KnowledgeStore()
results = store.search(query, limit=10)
```

Also fix `_generate_answer()` to use real LLM provider instead of template string.

**Verification:** GraphRAG query returns actual entities from KnowledgeStore.

## Risks and Mitigations
1. **Import cycles** — wave engines importing event bus could create circular imports → Mitigate with lazy imports inside try/except
2. **Performance** — 20 engines emitting events on every write could slow down → Mitigate with async event emission (fire-and-forget)
3. **Test regression** — changing engine behavior could break tests → Run 716 Beast Mode tests after each step
4. **ML model not trained** — risk_scorer needs training data → Use deterministic fallback when model has no training data

## Verification Steps
1. After Step 1: POST to any wave engine, verify TrustGraph node created
2. After Step 2: Create EDR detection, verify correlation engine receives signal
3. After Step 3: Add vulnerability, verify ML priority differs from severity-only
4. After Step 4: Query CISO dashboard with real org_id, verify non-zero dynamic values
5. After Step 5: GraphRAG query returns real entities, not mock
6. Final: 716/716 Beast Mode tests, 150/150 persona walkthrough
