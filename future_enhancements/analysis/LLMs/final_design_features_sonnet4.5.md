# FixOps – Final Feature Design

## 1. Current State Summary

### 1.1 Key Findings from Codebase Analysis

**Core Architecture**
- FastAPI-based enterprise backend (`fixops-enterprise/src/`) with modular service architecture
- Comprehensive CLI toolkit (`cli/`) with distinct commands: `fixops-ci`, `fixops-sbom`, `fixops-risk`, `fixops-provenance`, `fixops-repro`
- Decision engine (`DecisionEngine`) performs risk verdict derivation from findings with evidence generation, compliance evaluation, and marketplace recommendations
- Existing `CorrelationEngine` (disabled by default) in `fixops-enterprise/src/services/correlation_engine.py` with 5 correlation strategies

**Data Models & Types**
- No centralized `findings.py` or `events.py` model file exists
- Finding representations vary by source:
  - SARIF canonicalization in `core/sarif_canon.py` (normalizes to dict with `rule_id`, `severity`, `message`, `file_path`, `line_number`, `fingerprint`)
  - Automated pentest uses Pydantic `FindingInput` model with optional `id`, `rule_id`, `cve_id`, `cwe_id`, `severity`, `location`, `metadata`
  - Decision engine expects findings as `List[Dict[str, Any]]` with flexible schema (`severity`, `level`, `cve`, `cve_id`, `cveId` variants)
  - Normalizers in `apps/api/normalizers.py` handle SARIF, SBOM, CVE, Snyk formats

**Existing Correlation & Deduplication**
- `CorrelationEngine` implements 5 async strategies (feature-flagged, disabled by default):
  1. **Fingerprint**: Exact match on `fingerprint` field
  2. **Location**: File path + line proximity (±10 lines)
  3. **Pattern**: `rule_id` + `scanner_type` + `severity`
  4. **Root Cause**: Keyword-based categorization (input_validation, authentication, authorization, crypto, configuration)
  5. **Vulnerability**: CVE/CWE taxonomy matching
- Returns `CorrelationResult` with `confidence_score`, `noise_reduction_factor`, `correlation_type`, `correlated_findings` list
- Sub-millisecond performance target; batch processing with parallelism
- NO deduplication logic exists—correlation identifies related findings but does not merge/eliminate duplicates

**API Endpoints (v1)**
- `/api/v1/cicd/github/webhook`, `/jenkins/ingest`, `/sonarqube/ingest` — CI adapter ingestion
- `/api/v1/enhanced/analysis`, `/pipeline`, `/capabilities`, `/signals` — enhanced decision engine
- `/api/v1/evidence/{id}/verify` — evidence verification
- `/api/v1/micro-pentest/run`, `/status/{flow_id}`, `/batch` — PentAGI micro-pentest orchestration
- `/api/v1/automated-pentest/run`, `/narrative`, `/validate`, `/analyze` — automated pentest engine
- `/api/v1/artefacts/*`, `/marketplace/*`, `/pentagi/*`, `/advanced-pentest/*`, `/policy/*` — additional enterprise modules
- NO dedicated deduplication or correlation API endpoints

**CLI Commands**
- `fixops scan <path>` — scanner invocation (calls `/api/v1/scan`, not implemented in reviewed code)
- `fixops test <path>` — security tests
- `fixops monitor` — runtime monitoring
- `fixops auth login/logout` — authentication
- `fixops config` — configuration management
- `fixops-ci` orchestrator with subcommands: `sbom`, `risk`, `provenance`, `repro`, `evidence bundle`
- NO CLI flags for correlation/deduplication control

**YAML Configuration & Overlays**
- `config/fixops.overlay.yml` — comprehensive enterprise config with 582 lines
- Feature flags: `correlation_engine: {enabled: false}`, `modules.*`, `analysis_engines`, `compliance_analysis`, `mitre_mapping`
- Overlay mapping in `configs/overlay_mappings.yaml` — app/component regex matching
- Client-specific overlays in `configs/overlays/client.yaml`
- YAML merge behavior: standard key override; no evidence of custom deduplication config keys

### 1.2 Existing Strengths

- **Modular service architecture** with clear separation of concerns (decision, compliance, evidence, correlation)
- **Extensible API design** with FastAPI dependency injection, authentication middleware, and standardized error handling
- **Rich integration adapters** for GitHub, Jenkins, SonarQube with normalization logic
- **Feature flag infrastructure** via YAML overlay system enables gradual rollout
- **Performance-conscious** correlation engine with async/await, batch processing, sub-millisecond targets
- **Evidence & provenance** capabilities with signing, verification, immutability checks
- **Compliance framework mapping** (SOC2, ISO27001, PCI DSS, GDPR, HIPAA) embedded in decision engine
- **Automated pentest integration** with PentAGI, attack narrative generation, vulnerability validation
- **CLI orchestration** with evidence bundling, SBOM normalization, risk scoring, attestation workflows

### 1.3 Existing Gaps

**Deduplication**
- NO deduplication implementation exists
- Findings from multiple scanners/sources accumulate without merge/elimination logic
- No fingerprinting strategy for cross-scanner equivalence (e.g., Bandit finding ≈ Semgrep finding for same vulnerability)
- Risk of alert fatigue from duplicate findings across design/build/deploy/runtime lifecycle stages

**Correlation**
- Correlation engine exists but is **disabled by default** and not exposed via API/CLI
- No persistent correlation graph/store — correlation results are ephemeral per-request
- No cross-stage correlation (design-time findings → runtime events)
- No API endpoint to query/inspect correlation results
- No CLI command to trigger batch correlation

**Finding/Event Model Unification**
- No canonical data model — finding schema varies by ingestion source
- Inconsistent field naming: `cve` vs `cve_id` vs `cveId`, `severity` vs `level`, `id` vs `finding_id`
- No event model (runtime signals, telemetry, CNAPP exposures) integrated with static findings
- Lack of standardized `fingerprint` generation across all sources (only SARIF normalization generates it)

**Integration Inventory**
- CI/CD: GitHub (webhook), Jenkins (ingest), SonarQube (ingest) — **COMPLETE**
- Pentesting: PentAGI micro-pentest integration — **COMPLETE**
- Automated pentest: Internal engine with narrative generation — **COMPLETE**
- SBOM: lib4sbom parser, normalization — **COMPLETE**
- VEX: `VEXIngestor` is a **STUB** (placeholder with no processing logic)
- Container scanning: Trivy, Grype, Clair referenced in YAML but NO adapter code
- Cloud security: Prowler, Scout Suite, Forseti, AZSK referenced but NO adapter code
- API security: OWASP ZAP, Burp Suite referenced but NO adapter code
- SIEM/Telemetry: Fluent Bit, Vector config in YAML (`telemetry_bridge`) but NO ingestion endpoint
- Dependency scanning: Dependabot, Renovate mentioned but NO integration code
- Secrets scanning: Mentioned in risk modules but NO dedicated API endpoint
- License compliance: Risk module exists but NO API exposure

**Lifecycle Stage Tracking**
- Findings lack explicit lifecycle stage metadata (design/build/deploy/runtime)
- No unified view of finding evolution across stages
- Demo SSDLC stages (`demo_ssdlc_stages/`) are sample artifacts, not integrated into processing pipeline

**Storage & Indexing**
- Ephemeral in-memory stores (`EVIDENCE_STORE`, `DECISION_ENGINE` runtime globals)
- Evidence lake has retrieval but no query/search API for findings or correlations
- No graph database or indexing infrastructure for correlation edges

## 2. Feature 1: Deduplication & Correlation Engine

### 2.1 Problem Statement

FixOps ingests security findings from multiple sources (SAST, DAST, SCA, SBOM, micro-pentests, CNAPP) across four lifecycle stages (design, build, deploy, runtime). **Current gaps**:

1. **No deduplication**: Same vulnerability detected by 3 scanners creates 3 separate findings, inflating alert counts and obscuring signal.
2. **Correlation disabled**: Existing correlation engine is feature-flagged off; insights into related vulnerabilities (e.g., shared root cause, attack chain propagation) are unavailable.
3. **Cross-stage blindness**: Runtime exploit attempts cannot be linked back to design-time threat models or build-time SARIF findings.
4. **Inconsistent fingerprinting**: Only SARIF canonicalization generates fingerprints; SBOM CVEs, micro-pentest results, API-ingested findings lack stable identifiers.

**Impact**: Alert fatigue, duplicated remediation efforts, missed attack chain detection, poor compliance evidence traceability.

### 2.2 Design Goals

1. **Deterministic deduplication**: Merge duplicate findings from heterogeneous sources into canonical records with provenance tracking.
2. **Cross-stage correlation**: Link findings/events across design → build → deploy → runtime lifecycle.
3. **Graph-based relationships**: Model findings as nodes, correlations as edges (temporal, causal, spatial).
4. **Incremental enablement**: Feature-flag controlled rollout with backward compatibility.
5. **Performance**: Sub-second batch processing for 10k findings; real-time correlation for API ingestion.
6. **Explainability**: Provide rationale for deduplication merges and correlation groupings.

### 2.3 Canonical Finding/Event Model

**Unified Model** (extend existing dict-based patterns; avoid schema migration churn)

```
CanonicalFinding:
  # Stable identity
  id: UUID (generated if missing; DO NOT reuse scanner IDs)
  fingerprint: SHA256 hex (canonical deterministic hash)
  
  # Provenance
  source_type: enum [sarif, sbom_cve, micro_pentest, api_manual, runtime_event, cnapp_exposure]
  source_ids: list[str] (original scanner IDs that merged into this finding)
  lifecycle_stage: enum [design, build, deploy, runtime]
  first_seen: ISO8601 timestamp
  last_seen: ISO8601 timestamp
  
  # Vulnerability classification
  rule_id: str (scanner rule; nullable)
  cve_id: str (normalized CVE-YYYY-NNNNN; nullable)
  cwe_id: list[str] (CWE-NNN; nullable)
  title: str
  description: str
  severity: enum [critical, high, medium, low, info]
  cvss_score: float (nullable)
  
  # Location/context
  file_path: str (normalized forward-slash; nullable)
  line_number: int (nullable)
  component: str (SBOM component or service name; nullable)
  environment: str (production/staging/dev; nullable)
  
  # Exploit signals
  kev: bool (CISA KEV listed)
  epss: float (0.0-1.0; nullable)
  exploit_available: bool
  
  # Status & lifecycle
  status: enum [open, in_progress, resolved, suppressed, false_positive]
  resolution_rationale: str (nullable)
  
  # Correlation metadata
  correlation_groups: list[str] (group IDs this finding belongs to)
  related_findings: list[str] (finding IDs of correlated items)
  
  # Extensibility
  metadata: dict[str, Any] (scanner-specific fields, compliance mappings, etc.)
```

**Event Model Extension** (for runtime signals, CNAPP exposures)

```
RuntimeEvent:
  # Inherits all CanonicalFinding fields, plus:
  event_type: enum [exploit_attempt, anomaly_detection, policy_violation, exposure_detected]
  timestamp: ISO8601 (event occurrence time)
  source_ip: str (nullable)
  destination: str (nullable)
  severity_escalation: bool (if correlated to existing finding, was severity increased?)
  linked_finding_id: UUID (nullable; finding this event correlates to)
```

**Design Decision**: Reuse existing dict-based patterns with standardized keys rather than introducing Pydantic/dataclass models to minimize refactor impact. Validation occurs at API ingestion boundaries.

### 2.4 Deduplication Strategy

**Goal**: Merge functionally identical findings from different scanners into a single canonical record.

**Fingerprint Generation** (deterministic hash for deduplication)

1. **SARIF findings**: 
   - Hash input: `{normalized_file_path}:{line_number}:{rule_id}:{severity}`
   - Exclude scanner name, timestamps, run IDs
   
2. **SBOM CVE findings**:
   - Hash input: `{cve_id}:{component_name}:{component_version}`
   - Handles same CVE in different transitive dependencies as distinct findings
   
3. **Micro-pentest results**:
   - Hash input: `{cve_id}:{target_url}:{validation_status}`
   - Distinct from static findings due to runtime validation context
   
4. **API-ingested findings**:
   - Hash input: `{file_path}:{line_number}:{cve_id OR rule_id}:{severity}` (best-effort with available fields)
   
5. **Runtime events**:
   - Hash input: `{event_type}:{linked_finding_id OR file_path}:{destination}`
   - Events are NOT deduplicated (each occurrence is distinct) but MAY correlate to the same canonical finding

**Deduplication Algorithm**

```
1. Extract/compute fingerprint for incoming finding
2. Query deduplication index (in-memory dict or Redis) by fingerprint
3. IF match found:
   a. Merge provenance: append source_id to source_ids list
   b. Update last_seen timestamp
   c. Aggregate metadata: merge scanner-specific fields into metadata dict
   d. Reconcile conflicts:
      - Severity: KEEP HIGHEST (critical > high > medium > low)
      - CVE/CWE: UNION of all reported IDs
      - CVSS: KEEP HIGHEST score
      - Status: KEEP most severe (open > in_progress > resolved)
   e. Return existing finding ID
4. ELSE:
   a. Create new canonical finding
   b. Generate UUID
   c. Index by fingerprint
   d. Return new finding ID
```

**Conflict Resolution Rules**

- **Severity escalation**: If Scanner A reports "medium" and Scanner B reports "high" for same fingerprint, canonical severity = HIGH.
- **False positive handling**: If one source marks as false_positive, require 2+ sources to override (majority wins).
- **Location conflicts**: If line numbers differ by >50 lines, treat as distinct findings (likely different code blocks despite same rule_id).

**Noise Reduction Threshold**

- Target: 35-50% reduction in alert volume (based on existing correlation engine's 35% noise reduction goal)
- Metric: `unique_findings / total_ingested_findings`

### 2.5 Correlation Strategy

**Goal**: Identify relationships between distinct findings to reveal attack chains, blast radius, root causes.

**Extend Existing Correlation Engine** (reuse 5 strategies in `correlation_engine.py`)

1. **Fingerprint correlation** (existing) — KEEP AS-IS
2. **Location correlation** (existing) — EXTEND with component-level clustering for SBOM findings
3. **Pattern correlation** (existing) — ADD cross-scanner rule mapping (e.g., Bandit B201 ≈ Semgrep python.lang.security.audit.dangerous-pickle-use)
4. **Root cause correlation** (existing) — ENHANCE with CWE hierarchy traversal (CWE-89 SQL Injection → parent CWE-74 Injection)
5. **Vulnerability taxonomy** (existing) — ADD CVE-to-CWE mapping via NVD data
6. **Temporal correlation** (NEW) — Time-series analysis: findings that appear/disappear together across commits
7. **Cross-stage correlation** (NEW) — Link design-time threat models → build findings → runtime events
8. **Attack chain correlation** (NEW) — Use MITRE ATT&CK technique IDs from automated pentest narratives to link findings into multi-stage attack paths

**Correlation Graph Model**

```
Nodes: CanonicalFinding instances
Edges: CorrelationEdge
  source_finding_id: UUID
  target_finding_id: UUID
  correlation_type: enum [fingerprint, location, pattern, root_cause, vulnerability, temporal, cross_stage, attack_chain]
  confidence: float (0.0-1.0)
  metadata: dict (e.g., shared_cwe_id, attack_phase, time_delta_seconds)
  created_at: ISO8601
```

**Correlation Persistence** (NEW requirement)

- Store correlation graph in SQLite (low-scale) or PostgreSQL (enterprise) with `correlation_edges` table
- Support querying: "Show all findings correlated to CVE-2024-1234"
- Enrich decision engine compliance reports with correlation insights

**Cross-Stage Correlation Logic**

```
1. Design stage: Ingest threat model YAML (STRIDE categories, attack paths)
   - Extract asset/component names, threat types → store as design_findings
2. Build stage: Ingest SARIF findings
   - Match file_path to component from threat model → create cross_stage edge
3. Deploy stage: Ingest IaC scan results
   - Match resource_id (e.g., "AWS::EC2::Instance") to component → create edge
4. Runtime stage: Ingest CNAPP exposure alerts
   - Match destination IP/hostname to deployed component → create edge
   - IF exposure correlates to build-stage CVE → escalate severity
```

**Attack Chain Correlation** (leverage automated pentest output)

```
1. Automated pentest generates attack narratives with MITRE ATT&CK technique IDs
2. Extract technique IDs from findings (T1190, T1059, etc.)
3. Query MITRE ATT&CK matrix for technique relationships (T1190 → T1059 is common initial access → execution chain)
4. Create attack_chain edges between findings with sequential techniques
5. Prioritize findings that are part of multi-stage attack chains
```

### 2.6 API Enhancements / New APIs

**Enhance Existing Endpoints**

1. **POST `/api/v1/cicd/{github,jenkins,sonarqube}/ingest`**
   - **Change**: After decision engine evaluation, invoke deduplication + correlation
   - **Response addition**: 
     ```json
     {
       "deduplication": {
         "total_findings": 150,
         "unique_findings": 92,
         "duplicates_merged": 58,
         "noise_reduction": 0.387
       },
       "correlation": {
         "correlated_groups": 12,
         "high_confidence_correlations": 8,
         "attack_chains_detected": 2
       }
     }
     ```

2. **POST `/api/v1/enhanced/analysis`**
   - **Change**: Include correlation graph context in LLM prompts for enhanced decision consensus
   - **Response addition**: Add `correlation_insights` field with attack chain summaries

**New Endpoints**

3. **POST `/api/v1/findings/deduplicate`** (NEW)
   - **Purpose**: Trigger batch deduplication for uploaded findings array
   - **Request**: `{ "findings": [...], "options": { "dry_run": bool } }`
   - **Response**: Deduplicated findings list + merge audit trail
   - **Auth**: Requires authentication
   
4. **POST `/api/v1/findings/correlate`** (NEW)
   - **Purpose**: Run correlation analysis on existing findings store
   - **Request**: `{ "finding_ids": [...] | "all": true, "strategies": [...] }`
   - **Response**: `{ "correlations": [CorrelationEdge], "graph_stats": {...} }`
   - **Auth**: Requires authentication
   
5. **GET `/api/v1/findings/{id}/related`** (NEW)
   - **Purpose**: Retrieve all findings correlated to a specific finding
   - **Query params**: `?correlation_type=attack_chain&min_confidence=0.7`
   - **Response**: List of related findings with correlation metadata
   - **Auth**: Requires authentication
   
6. **GET `/api/v1/findings/attack-chains`** (NEW)
   - **Purpose**: List detected multi-stage attack chains
   - **Response**: `{ "chains": [{ "stages": [...], "risk_score": float, "mitre_techniques": [...] }] }`
   - **Auth**: Requires authentication

7. **POST `/api/v1/events/ingest`** (NEW)
   - **Purpose**: Ingest runtime events (SIEM, CNAPP, telemetry) with automatic cross-stage correlation
   - **Request**: `{ "events": [RuntimeEvent], "auto_correlate": bool }`
   - **Response**: Event IDs + correlation results to existing findings
   - **Auth**: Requires authentication

**Backward Compatibility**

- All existing endpoints remain unchanged in request/response schema
- New fields are additive (nullable/optional)
- Deduplication/correlation is feature-flagged: if disabled, endpoints return empty metadata

### 2.7 CLI Changes

**Enhance Existing Commands**

1. **`fixops scan <path>`**
   - **Add flag**: `--deduplicate` (default: true) — enable/disable deduplication
   - **Add flag**: `--correlate` (default: false) — run correlation analysis post-scan
   - **Output change**: Print deduplication stats in summary table

2. **`fixops-ci evidence bundle`**
   - **Add flag**: `--include-correlation-graph` — embed correlation edges in evidence bundle
   - **Behavior**: Evidence bundle JSON includes `correlation_graph` section with nodes/edges

**New Commands**

3. **`fixops findings deduplicate <input.json>`** (NEW)
   - **Purpose**: Offline batch deduplication of findings JSON/SARIF files
   - **Flags**: 
     - `--output <file>` — write deduplicated findings
     - `--strategy <merge|replace>` — merge metadata or replace with latest
   - **Example**: `fixops findings deduplicate sarif/*.json --output deduplicated.json`

4. **`fixops findings correlate <input.json>`** (NEW)
   - **Purpose**: Run correlation analysis and output graph
   - **Flags**:
     - `--strategies <fingerprint,location,attack_chain>` — select strategies
     - `--format <json|dot|graphml>` — output format
   - **Example**: `fixops findings correlate findings.json --format dot > graph.dot`

5. **`fixops findings query --related-to <finding-id>`** (NEW)
   - **Purpose**: CLI query interface for correlation graph
   - **Flags**:
     - `--correlation-type <type>`
     - `--min-confidence <0.0-1.0>`
   - **Output**: Table of related findings with correlation metadata

**CLI Configuration Resolution** (extend existing `config.py`)

- Add `~/.fixops/config.yaml` section:
  ```yaml
  deduplication:
    enabled: true
    fingerprint_strategy: auto  # auto, strict, lenient
  correlation:
    enabled: false
    default_strategies:
      - fingerprint
      - location
      - root_cause
    min_confidence: 0.6
  ```

### 2.8 YAML Overlay Changes

**Extend `config/fixops.overlay.yml`**

1. **Enable correlation engine by default** (currently disabled)
   ```yaml
   modules:
     correlation_engine:
       enabled: true  # CHANGE FROM false
       strategies:
         - fingerprint
         - location
         - pattern
         - root_cause
         - vulnerability
         - temporal          # NEW
         - cross_stage       # NEW
         - attack_chain      # NEW
       noise_reduction_target: 0.35
       persistence:
         enabled: true
         backend: sqlite  # or postgresql
         connection_string_env: FIXOPS_CORRELATION_DB
   ```

2. **Add deduplication config** (NEW section)
   ```yaml
   modules:
     deduplication:
       enabled: true
       fingerprint_algorithm: sha256
       conflict_resolution:
         severity: highest
         cvss: highest
         status: most_severe
       false_positive_threshold: 2  # require 2+ sources to override FP
   ```

3. **Add lifecycle stage tracking** (NEW section)
   ```yaml
   lifecycle:
     stages:
       - design
       - build
       - deploy
       - runtime
     stage_detection:
       design:
         match_patterns: ["threat_model", "architecture_review"]
       build:
         match_patterns: ["sarif", "sbom", "sast", "sca"]
       deploy:
         match_patterns: ["terraform_plan", "kubernetes_manifest", "iac_scan"]
       runtime:
         match_patterns: ["cnapp", "siem", "telemetry", "waf_logs"]
   ```

**Overlay Merge Behavior** (existing mechanism)

- Client-specific overlays in `configs/overlays/*.yaml` can override:
  - `modules.deduplication.enabled: false` (opt-out for specific clients)
  - `modules.correlation_engine.strategies: [fingerprint, location]` (reduce strategies for performance)

**Validation**: Ensure YAML schema validation in `core/configuration.py` accepts new keys without breaking existing configs.

### 2.9 Risks & Mitigations

**Risk 1: Fingerprint Collisions**
- **Scenario**: Two unrelated findings hash to same fingerprint due to similar location + rule_id
- **Likelihood**: Low (SHA256 collision resistant; includes file_path + line_number)
- **Mitigation**: 
  - Add secondary verification: if fingerprints match but descriptions differ significantly (edit distance > 0.5), treat as separate findings
  - Log fingerprint collisions for manual review

**Risk 2: Performance Degradation**
- **Scenario**: 10k+ findings batch deduplication causes API timeout
- **Likelihood**: Medium (current correlation engine targets sub-millisecond but no dedup tested at scale)
- **Mitigation**:
  - Implement async background job for large batches (Celery/RQ)
  - Redis-backed fingerprint index for O(1) lookups
  - Circuit breaker: if deduplication takes >5s, return raw findings + queue background job

**Risk 3: False Deduplication (Over-Merging)**
- **Scenario**: Same rule_id in same file but different vulnerability contexts merged incorrectly
- **Likelihood**: Medium (line number proximity heuristic may fail for dense code)
- **Mitigation**:
  - Require fingerprint AND at least one additional field match (CWE, CVE, or message similarity >0.8)
  - Provide `/api/v1/findings/{id}/unmerge` endpoint to split incorrectly merged findings

**Risk 4: Correlation False Positives**
- **Scenario**: Unrelated findings correlated due to keyword overlap in root cause analysis
- **Likelihood**: Medium (existing correlation engine uses broad keyword matching)
- **Mitigation**:
  - Confidence scores: require confidence >0.7 for actionable correlations
  - User feedback loop: `/api/v1/findings/{id}/dismiss-correlation` to train model

**Risk 5: Storage Growth**
- **Scenario**: Correlation graph edges grow quadratically with findings
- **Likelihood**: High (1000 findings → up to 1M edges if all-to-all correlated)
- **Mitigation**:
  - Prune low-confidence edges (confidence <0.5) after 30 days
  - Limit correlation to findings in same lifecycle stage + cross-stage only for critical/high severity
  - Implement graph compaction: merge transitive edges (A→B, B→C becomes A→C)

**Risk 6: Schema Inconsistency**
- **Scenario**: Existing findings in evidence store lack new required fields (fingerprint, lifecycle_stage)
- **Likelihood**: High (migration required)
- **Mitigation**:
  - Backward-fill fingerprints on first access (lazy migration)
  - Default lifecycle_stage to "build" for legacy findings
  - Add `/api/v1/admin/migrate-findings` endpoint for bulk backfill

**Risk 7: MITRE ATT&CK Mapping Drift**
- **Scenario**: Automated pentest's MITRE technique mappings become stale as ATT&CK matrix updates
- **Likelihood**: Medium (ATT&CK updates quarterly)
- **Mitigation**:
  - Pin MITRE ATT&CK matrix version in config (e.g., `mitre_attack_version: v14.1`)
  - Periodic background job to refresh mappings from MITRE GitHub repo
  - Log warnings when deprecated techniques detected

## 3. Feature 2: Integrations (Audit + Completion)

### 3.1 Integration Inventory (Stub / Partial / Complete)

**COMPLETE** (actively used, full adapter code exists)

| Integration | Type | Location | Ingestion Endpoint | Notes |
|-------------|------|----------|-------------------|-------|
| GitHub | CI/CD | `integrations/github/adapter.py` | `/api/v1/cicd/github/webhook` | Pull request, check suite events |
| Jenkins | CI/CD | `integrations/jenkins/adapter.py` | `/api/v1/cicd/jenkins/ingest` | SARIF/SBOM ingestion |
| SonarQube | CI/CD | `integrations/sonarqube/adapter.py` | `/api/v1/cicd/sonarqube/ingest` | Issues normalization |
| PentAGI | Pentest | `fixops-enterprise/src/api/v1/micro_pentest.py` | `/api/v1/micro-pentest/run` | Flow orchestration via REST |
| Automated Pentest | Internal | `fixops-enterprise/src/services/automated_pentest.py` | `/api/v1/automated-pentest/run` | Narrative generation, validation |
| SBOM (lib4sbom) | Supply Chain | `apps/api/normalizers.py` | Various | CycloneDX, SPDX parsing |

**PARTIAL** (referenced in code, incomplete implementation)

| Integration | Type | Location | Status | Gap |
|-------------|------|----------|--------|-----|
| Evidence Lake | Storage | `fixops-enterprise/src/services/evidence_lake.py` | Retrieval only | NO write/query API |
| Telemetry Bridge | Observability | YAML config only (`telemetry_bridge`) | No ingestion endpoint | Fluent Bit/Vector config exists but no API route |
| MITRE Compliance | Analysis | YAML config only (`mitre_mapping.enabled: false`) | Disabled | No analyzer service implementation |
| Compliance Analysis | Policy | YAML config only (`compliance_analysis.enabled: false`) | Disabled | Framework mappings exist but no execution engine |

**STUB** (placeholder code with no real logic)

| Integration | Type | Location | Issue |
|-------------|------|----------|-------|
| VEX | Vulnerability Exchange | `fixops-enterprise/src/services/vex_ingestion.py` | `VEXIngestor` is a dict accumulator with no VEX schema validation or advisory processing |
| Feeds Service | Threat Intel | `fixops-enterprise/src/services/feeds_service.py` | Empty scheduler loop; no CVE/KEV feed fetching logic |

**MISSING** (referenced in YAML but NO code exists)

| Integration | Type | YAML Reference | Criticality |
|-------------|------|----------------|-------------|
| Trivy | Container | `analysis_engines.container.oss_fallback.tools` | HIGH (OSS container scanning leader) |
| Grype | Container | Same as above | MEDIUM (alternative to Trivy) |
| Clair | Container | Same as above | LOW (legacy, less active) |
| Prowler | Cloud | `analysis_engines.cloud.cspm.oss_fallback.tools` | HIGH (AWS/Azure/GCP misconfig detection) |
| Scout Suite | Cloud | Same as above | MEDIUM (multi-cloud security auditing) |
| Forseti | Cloud | `analysis_engines.cloud.cspm.oss_fallback.tools.gcp` | LOW (GCP-specific, deprecated by Google) |
| OWASP ZAP | DAST | `analysis_engines.api.oss_fallback.tools` | HIGH (dynamic API security testing) |
| Dependabot | Dependency | `analysis_engines.remediation.oss_fallback.tools` | MEDIUM (GitHub native, auto-PR creation) |
| Renovate | Dependency | Same as above | MEDIUM (multi-platform dependency updates) |
| Semgrep | SAST | `analysis_engines.languages.*.oss_fallback.tools` | HIGH (multi-language, widely adopted) |
| Bandit | SAST | `analysis_engines.languages.python.oss_fallback.tools` | MEDIUM (Python security linter) |
| ESLint | SAST | `analysis_engines.languages.javascript.oss_fallback.tools` | MEDIUM (JS/TS linting) |
| Gosec | SAST | `analysis_engines.languages.go.oss_fallback.tools` | MEDIUM (Go security scanner) |
| Checkov | IaC | `analysis_engines.iac.*.oss_fallback.tools` | HIGH (Terraform, CloudFormation, K8s scanning) |

### 3.2 Missing Critical Integrations

**Priority 1 (Enterprise Blockers)**

1. **Trivy** (Container Scanning)
   - **Justification**: Industry-standard OSS container/image scanner; 20k+ GitHub stars; SARIF output native
   - **Use case**: Scan Docker images in CI/CD → ingest vulnerabilities into FixOps correlation engine
   - **Gap impact**: Cannot detect container layer CVEs without manual SARIF upload

2. **Prowler** (Cloud Security Posture)
   - **Justification**: AWS/Azure/GCP misconfiguration detection; CIS benchmark compliance; JSON/CSV output
   - **Use case**: Daily scheduled scans of cloud accounts → ingest as `design` stage findings (infrastructure-as-code gaps)
   - **Gap impact**: No cloud-native security findings; IaC scans limited to Terraform static analysis

3. **OWASP ZAP** (Dynamic API Testing)
   - **Justification**: DAST for APIs; REST/GraphQL scanning; active vulnerability probing
   - **Use case**: Post-deploy automated scans → ingest as `runtime` stage findings with cross-stage correlation to SAST results
   - **Gap impact**: No runtime validation of static findings; SSRF, authentication bypasses undetected

4. **Semgrep** (SAST)
   - **Justification**: Fast multi-language static analysis; extensive rule registry; SARIF output
   - **Use case**: Build-time code scanning → primary SAST engine for OSS fallback strategy
   - **Gap impact**: Heavy reliance on proprietary SAST engines; no OSS fallback if license issues

**Priority 2 (Operational Value)**

5. **VEX Ingestion** (complete the stub)
   - **Justification**: CSAF/CycloneDX VEX advisories provide vendor "not affected" statements → reduce false positives
   - **Use case**: Import VEX documents → suppress findings for CVEs confirmed as not exploitable in specific contexts
   - **Gap impact**: Manual false positive triage; no automated suppression based on vendor advisories

6. **Fluent Bit / Vector Telemetry** (complete the partial)
   - **Justification**: Runtime log/metrics ingestion → detect exploit attempts, anomalies
   - **Use case**: WAF logs, application traces → correlation with build-time CVE findings → severity escalation
   - **Gap impact**: No runtime observability integration; cannot link attacks to vulnerable code

7. **Dependabot / Renovate** (Dependency Management)
   - **Justification**: Automated dependency update PRs with CVE remediation tracking
   - **Use case**: Webhook ingestion of PR metadata → track remediation lifecycle → close findings when patched version merged
   - **Gap impact**: Manual tracking of remediation; no automated finding closure

**Priority 3 (Nice-to-Have)**

8. **Checkov** (IaC Scanning)
   - **Justification**: Policy-as-code for Terraform, CloudFormation, Kubernetes; JSON output
   - **Use case**: Pre-deploy IaC validation → ingest as `deploy` stage findings
   - **Gap impact**: Reliance on proprietary IaC scanners; no OSS option

9. **Scout Suite** (Cloud Auditing)
   - **Justification**: Multi-cloud security assessment; HTML/JSON reports
   - **Use case**: Scheduled cloud account audits → ingest as `runtime` compliance findings
   - **Gap impact**: Limited to Prowler; less comprehensive cloud coverage

### 3.3 Design for Completion

**Adapter Design Pattern** (reuse existing CI adapter structure)

```
IntegrationAdapter (abstract base)
  - normalize(raw_output: dict) -> List[CanonicalFinding]
  - ingest(payload: dict) -> DecisionOutcome
  - health_check() -> bool

TrivyAdapter(IntegrationAdapter)
  - parse_trivy_json(output: dict) -> List[CanonicalFinding]
    - Extract vulnerabilities from JSON schema
    - Map Trivy severity to FixOps enum
    - Generate fingerprint: sha256({image_digest}:{cve_id}:{package})
  - ingest(payload) -> calls DecisionEngine.evaluate()

ProwlerAdapter(IntegrationAdapter)
  - parse_prowler_csv(output: str) -> List[CanonicalFinding]
    - Parse CSV with CHECK_ID, SEVERITY, RESOURCE_ID
    - Map to CanonicalFinding with source_type=cnapp_exposure
    - lifecycle_stage=design (infrastructure findings)

OwaspZapAdapter(IntegrationAdapter)
  - parse_zap_json(output: dict) -> List[CanonicalFinding]
    - Extract alerts with URL, risk level, CWE
    - Generate fingerprint: sha256({url}:{attack}:{cwe_id})
    - lifecycle_stage=runtime (DAST findings)
```

**Minimal Implementation Approach**

1. **Trivy**:
   - Input: Trivy JSON output (via `trivy image --format json`)
   - Normalization: Map `Results[].Vulnerabilities[]` to CanonicalFinding
   - API route: `POST /api/v1/cicd/trivy/ingest`
   - CLI: `fixops scan --scanner trivy <image>`
   - Effort: ~2 days (JSON schema well-documented)

2. **Prowler**:
   - Input: Prowler JSON output (`prowler aws --output-formats json`)
   - Normalization: Map `findings[]` with CIS benchmark IDs → CanonicalFinding
   - API route: `POST /api/v1/cicd/prowler/ingest`
   - Scheduled task: Add to `FeedsService` for daily cloud scans
   - Effort: ~3 days (CSV/JSON formats; AWS/Azure/GCP credential handling)

3. **OWASP ZAP**:
   - Input: ZAP JSON report (`zap-cli --format json`)
   - Normalization: Map `site[].alerts[]` → CanonicalFinding with runtime stage
   - API route: `POST /api/v1/cicd/zap/ingest`
   - Cross-stage correlation: Link ZAP alerts to SARIF findings by URL path → file path mapping
   - Effort: ~3 days (ZAP API integration, URL normalization)

4. **Semgrep**:
   - Input: Semgrep SARIF output (`semgrep --sarif`)
   - Reuse: Existing SARIF canonicalization in `core/sarif_canon.py`
   - API route: `POST /api/v1/cicd/semgrep/ingest` (alias to generic SARIF ingestion)
   - YAML config: Add to `oss_tools.yml` with rule registry path
   - Effort: ~1 day (SARIF already supported)

5. **VEX Ingestion** (complete stub):
   - Input: CycloneDX VEX JSON or CSAF documents
   - Processing:
     - Parse `vulnerabilities[].analysis.state` (exploitable, not_affected, in_triage)
     - Match CVE IDs to existing findings
     - Update finding status to `suppressed` if `not_affected` with rationale
   - API route: `POST /api/v1/vex/ingest`
   - Effort: ~2 days (CSAF schema complex; CycloneDX VEX simpler)

6. **Telemetry Ingestion** (complete partial):
   - Input: Fluent Bit HTTP output (`@type http`), Vector HTTP sink
   - Processing:
     - Extract structured logs (JSON)
     - Match anomaly patterns (SQL injection signatures, XSS payloads)
     - Create RuntimeEvent with linked_finding_id via CVE correlation
   - API route: `POST /api/v1/events/ingest` (reuse from Section 2.6)
   - Effort: ~4 days (log parsing, anomaly detection heuristics)

**Integration Testing Strategy**

- **Fixtures**: Store sample Trivy JSON, Prowler CSV, ZAP JSON in `fixtures/` directory
- **Unit tests**: Parse sample outputs → verify CanonicalFinding schema compliance
- **Integration tests**: Mock DecisionEngine → verify adapter calls with correct payloads
- **E2E tests**: CLI command → API ingestion → correlation → evidence bundle generation

### 3.4 API / CLI / YAML Implications

**API Additions**

- `POST /api/v1/cicd/trivy/ingest`
- `POST /api/v1/cicd/prowler/ingest`
- `POST /api/v1/cicd/zap/ingest`
- `POST /api/v1/cicd/semgrep/ingest`
- `POST /api/v1/vex/ingest`
- All follow existing adapter pattern: accept JSON payload → normalize → evaluate → return DecisionOutcome

**CLI Extensions**

- `fixops scan --scanner trivy <target>` — invoke Trivy, upload results
- `fixops scan --scanner prowler --cloud aws` — run Prowler, upload results
- `fixops scan --scanner zap <url>` — run ZAP, upload results
- `fixops vex import <vex.json>` — bulk VEX advisory import

**YAML Configuration**

- Add to `config/oss_tools.yml`:
  ```yaml
  trivy:
    enabled: true
    binary_path: /usr/local/bin/trivy
    default_format: json
    scan_timeout_seconds: 300
  
  prowler:
    enabled: true
    binary_path: /usr/local/bin/prowler
    output_directory: /tmp/prowler
    cloud_accounts:
      - profile: production-aws
        regions: [us-east-1, us-west-2]
  
  owasp_zap:
    enabled: true
    api_url: http://localhost:8080
    api_key_env: ZAP_API_KEY
    scan_policies: [default, api-scan]
  ```

**Feature Flags** (extend `fixops.overlay.yml`)

```yaml
integrations:
  trivy:
    enabled: true
    auto_ingest_ci: true  # automatically scan in CI pipeline
  prowler:
    enabled: false  # requires cloud credentials
  owasp_zap:
    enabled: true
    post_deploy_scan: true  # trigger DAST after deployment
  vex:
    enabled: true
    auto_suppress: true  # automatically suppress not_affected CVEs
```

### 3.5 Risks & Mitigations

**Risk 1: Scanner Availability / Licensing**
- **Scenario**: Trivy/ZAP require Docker runtime or network access; Prowler needs AWS credentials
- **Mitigation**: Graceful degradation — if scanner binary missing, log warning + skip. Add `scanner_available()` health check to adapters.

**Risk 2: Output Format Drift**
- **Scenario**: Trivy v0.50 changes JSON schema, breaks parser
- **Mitigation**: Pin scanner versions in CI/CD (Docker images). Add schema version detection + backward compatibility shims.

**Risk 3: Performance Impact**
- **Scenario**: Prowler scans 1000+ AWS resources → 10-minute API call
- **Mitigation**: Async job processing. POST to `/ingest` returns `202 Accepted` with job ID; poll `/jobs/{id}/status` for completion.

**Risk 4: Credential Management**
- **Scenario**: Prowler AWS keys, ZAP API key leakage in logs
- **Mitigation**: Use environment variables only (`AWS_PROFILE`, `ZAP_API_KEY`). Never log credential values. Add `secrets_models.py` encryption for stored credentials.

**Risk 5: False Positive Inflation**
- **Scenario**: ZAP DAST reports many low-confidence alerts → noise increase
- **Mitigation**: Add confidence threshold in YAML config (`owasp_zap.min_confidence: 2`). Map ZAP confidence (0-3) to FixOps confidence (0.0-1.0).

## 4. Non-Goals

**Explicitly Out of Scope** (will NOT be built in this design)

1. **Automated Remediation Execution**
   - NO auto-applying patches, code fixes, or config changes
   - FixOps provides recommendations; human/external tool applies changes
   - Rationale: Safety, auditability, enterprise change control requirements

2. **Real-Time Exploit Blocking**
   - NO WAF/IPS functionality; no active blocking of runtime attacks
   - FixOps ingests telemetry for analysis, does NOT enforce controls
   - Rationale: FixOps is observability + decision plane, not data plane

3. **Custom Scanner Development**
   - NO building new SAST/DAST/SCA engines from scratch
   - Integration layer only; scanners are external dependencies
   - Rationale: Leverage mature OSS/commercial tools; focus on orchestration

4. **Machine Learning Model Training**
   - NO training custom ML models for correlation or deduplication
   - Use rule-based heuristics + confidence scoring
   - Rationale: Avoid ML infrastructure complexity, training data requirements, explainability challenges

5. **Graph Database Migration**
   - NO Neo4j, JanusGraph, or dedicated graph DB in initial rollout
   - Use SQLite/PostgreSQL with edge table for correlation graph
   - Rationale: Minimize operational overhead; most graphs <10k nodes (manageable in RDBMS)

6. **Bi-Directional Integration Sync**
   - NO writing back to GitHub Issues, Jira tickets, etc. (read-only integrations)
   - Evidence bundles/reports can be manually uploaded to external systems
   - Rationale: Avoid complex state synchronization, permission sprawl

7. **Multi-Tenancy for Correlation Graph**
   - NO tenant isolation in correlation graph (single global graph per deployment)
   - Each organization runs separate FixOps instance
   - Rationale: Avoid cross-tenant data leakage; simpler security model

8. **Historical Trend Analysis**
   - NO time-series dashboards showing finding trends over months
   - Focus on point-in-time correlation + lifecycle tracking
   - Rationale: Analytics module exists but not prioritized; requires separate data warehouse

9. **Compliance Report Generation**
   - NO generating PDF compliance reports (SOC2, PCI DSS audit documents)
   - Provide compliance mapping data; external tools render reports
   - Rationale: Report formatting is presentational, not analytical

10. **Threat Intelligence Feed Aggregation**
    - NO fetching CVE feeds, KEV lists, EPSS scores automatically in this phase
    - Assume feeds are manually uploaded or externally managed
    - Rationale: Feeds service is stub; requires rate limiting, caching, license compliance

## 5. Implementation Readiness Checklist

**Pre-Implementation Requirements** (must be TRUE before coding starts)

### 5.1 Technical Prerequisites

- [ ] **Database Schema Designed**: Correlation graph tables (`correlation_edges`, `canonical_findings`) with indexes on fingerprint, finding_id, correlation_type
- [ ] **Fingerprint Algorithm Validated**: Unit tests confirm SHA256 fingerprint uniqueness for 100k diverse findings (collision rate <0.001%)
- [ ] **API Versioning Strategy**: Confirm v1 API changes are additive-only; v2 API planning if breaking changes needed
- [ ] **Feature Flag Infrastructure**: Validate existing YAML overlay system can toggle deduplication/correlation per client
- [ ] **Performance Benchmark Baseline**: Measure current correlation engine latency (disabled) vs enabled with 1k/10k/100k findings

### 5.2 Data Migration

- [ ] **Legacy Finding Backfill Plan**: Script to generate fingerprints for existing findings in evidence store (dry-run tested)
- [ ] **Lifecycle Stage Inference Logic**: Heuristics to classify existing findings as build/deploy/runtime based on source_type or metadata
- [ ] **Rollback Procedure**: Documented steps to disable deduplication + restore raw findings if correlation graph corrupts

### 5.3 Integration Readiness

- [ ] **Scanner Availability Matrix**: Confirm which scanners (Trivy, Prowler, ZAP) are available in CI/CD environments
- [ ] **Credential Management**: AWS, Azure, GCP service accounts provisioned for Prowler; ZAP API keys generated
- [ ] **Sample Data Collected**: Real Trivy JSON, Prowler CSV, ZAP JSON outputs from target environments for parser development
- [ ] **VEX Schema Selection**: Decide CycloneDX VEX vs CSAF (recommend CycloneDX for simplicity; SARIF-adjacent ecosystem)

### 5.4 Operational Readiness

- [ ] **Monitoring & Alerting**: Metrics for deduplication rate, correlation graph size, API latency added to observability stack
- [ ] **Log Sanitization**: Audit all new API routes for PII/credential leakage in logs (especially Prowler AWS account IDs)
- [ ] **Documentation Updated**: API reference docs, CLI `--help` text, YAML schema docs reflect new endpoints/flags
- [ ] **Compliance Review**: Legal/security review of correlation graph data retention (GDPR, SOC2 implications)

### 5.5 Testing Strategy

- [ ] **Unit Tests**: ≥80% coverage for fingerprint generation, deduplication merge logic, correlation strategies
- [ ] **Integration Tests**: Mock external scanners (Trivy, Prowler, ZAP); verify adapter normalization
- [ ] **Performance Tests**: Load test `/api/v1/findings/correlate` with 10k findings; confirm <5s response time
- [ ] **Regression Tests**: Existing CI/CD ingestion endpoints continue to work with deduplication disabled
- [ ] **Chaos Tests**: Simulate fingerprint collision, database deadlock, correlation graph cycle → verify graceful degradation

### 5.6 Stakeholder Alignment

- [ ] **Product Requirements Validated**: Confirm noise reduction target (35-50%) aligns with customer expectations
- [ ] **UX Review**: Frontend team confirms correlation graph visualization feasibility (if UI planned)
- [ ] **Customer Advisory Board Feedback**: Present design to 3-5 enterprise users; collect feasibility concerns
- [ ] **Security Audit**: Threat model correlation graph API endpoints; confirm no IDOR, injection, DoS vectors

### 5.7 Dependency Management

- [ ] **Library Upgrades Planned**: Check if `pgmpy`, `networkx`, `lib4sbom` require version bumps for new features
- [ ] **Docker Image Updates**: Trivy, Prowler, ZAP Dockerfiles prepared for scanner integrations
- [ ] **Database Connector**: Confirm SQLAlchemy/asyncpg supports correlation graph edge table schema

### 5.8 Rollout Strategy

- [ ] **Feature Flag Rollout Plan**: Week 1 (internal testing), Week 2 (opt-in customers), Week 4 (default-on)
- [ ] **Canary Deployment**: 5% of API traffic routes to deduplication-enabled backend; monitor error rates
- [ ] **Rollback Trigger**: Define metrics threshold (e.g., >10% API error rate, >2s latency regression) for automatic disable
- [ ] **Customer Communication**: Release notes, migration guides, FAQ drafted for deduplication/correlation features

### 5.9 Known Blockers (Must Resolve)

- [ ] **BLOCKER**: `VEXIngestor` stub must be completed OR removed if VEX integration deferred to Phase 2
- [ ] **BLOCKER**: Decision on correlation graph storage backend (SQLite for demo, PostgreSQL for production?)
- [ ] **BLOCKER**: Clarify if MITRE ATT&CK data bundled in repo or fetched at runtime (licensing implications)

### 5.10 Success Criteria (Measurable)

- [ ] **Deduplication Effectiveness**: Achieve 35-50% reduction in unique findings across 10 diverse customer codebases
- [ ] **Correlation Accuracy**: ≥70% of high-confidence correlations validated as true positives by security engineers
- [ ] **Performance**: API `/correlate` endpoint processes 10k findings in <3 seconds (p95)
- [ ] **Adoption**: 60% of customers enable deduplication within 3 months of GA release
- [ ] **Integration Coverage**: 4/6 priority integrations (Trivy, Prowler, ZAP, Semgrep) live in production by GA

---

**Design Document Version**: 1.0  
**Last Updated**: 2025-12-25  
**Status**: Ready for Technical Review  
**Reviewers Required**: Backend Lead, Security Architect, Product Manager, DevOps Lead
