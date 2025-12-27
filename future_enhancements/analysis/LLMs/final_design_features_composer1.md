# FixOps – Final Feature Design

## 1. Current State Summary

### Key Findings from Codebase Analysis

**Core Services/Modules:**
- `PipelineOrchestrator` (`apps/api/pipeline.py`) orchestrates SSDLC stages (design, sbom, sarif, cve, vex, cnapp, context)
- `CorrelationEngine` (`fixops-enterprise/src/services/correlation_engine.py`) exists but disabled by default (feature flag `ENABLE_CORRELATION_ENGINE`)
- `IdentityResolver` (`core/services/identity.py`) provides fingerprinting (`compute_fingerprint`, `compute_correlation_key`) but not integrated into ingestion pipeline
- `ProcessingLayer` implements Bayesian/Markov analysis but no cross-stage deduplication
- Data models: `Finding` (`core/analytics_models.py`), `SecretFinding` (`core/secrets_models.py`), normalized SARIF/SBOM/CVE/VEX/CNAPP models

**API Endpoints:**
- Ingestion: `/inputs/{stage}` (design, sbom, sarif, cve, vex, cnapp, context) with chunked upload support
- Pipeline: `/pipeline/run` (orchestrates all stages)
- Triage: `/api/v1/triage` (transforms pipeline results to triage format)
- Graph: `/api/v1/graph` (knowledge graph visualization)
- Enterprise: `/api/v1/micro-pentest/run`, `/api/v1/cicd/{github,jenkins,sonarqube}/ingest`
- Integrations: `/api/v1/integrations` (CRUD + test/sync endpoints)

**CLI Commands:**
- `fixops scan <path>` - Code scanning (calls `/api/v1/scan`)
- `fixops test <path>` - Security tests
- `fixops monitor` - Runtime monitoring
- `fixops-ci {sbom,risk,provenance,repro,evidence}` - Supply chain workflows
- Config: `fixops config {set_api_url,show}`

**YAML/Config Overlays:**
- `config/fixops.overlay.yml` - Main overlay with module toggles, compliance frameworks, guardrails
- `configs/overlay_mappings.yaml` - App/component matching patterns
- Feature flags via `core/flags/` (local/LD providers)
- Module enablement: `modules.correlation_engine.enabled: false` (default)

**Existing Deduplication/Correlation:**
- `CorrelationEngine` implements 5 strategies (fingerprint, location, pattern, root_cause, vulnerability) but not invoked in pipeline
- `IdentityResolver.compute_fingerprint()` exists but not used during ingestion
- `core/oss_fallback.py` has basic deduplication (same file, line, rule_id) for OSS tool results only
- No cross-stage deduplication (design-time findings vs build-time vs runtime)

**Integrations Status:**
- **GitHub** (`integrations/github/adapter.py`): Complete adapter, webhook handler in `/api/v1/cicd/github/webhook`
- **Jenkins** (`integrations/jenkins/adapter.py`): Complete adapter, ingest endpoint `/api/v1/cicd/jenkins/ingest`
- **SonarQube** (`integrations/sonarqube/adapter.py`): Complete adapter, ingest endpoint `/api/v1/cicd/sonarqube/ingest`
- **PentAGI** (`fixops-enterprise/src/api/v1/micro_pentest.py`): Complete micro-pentest integration
- **Jira/Confluence** (`core/connectors.py`): Connectors exist, referenced in integrations router but may be stubs
- **Slack** (`core/connectors.py`): Connector exists, test endpoint available

### Existing Strengths

- Modular architecture with clear separation (normalizers, pipeline, decision engine)
- Feature flag system enables gradual rollout
- Comprehensive data models (Finding, Decision, normalized inputs)
- Correlation engine code exists (needs activation/integration)
- Fingerprinting utilities exist in IdentityResolver
- Multi-stage ingestion pipeline (design → build → deploy → runtime)
- Knowledge graph construction (`new_apps/api/processing/knowledge_graph.py`)

### Existing Gaps

- **Deduplication**: No unified deduplication across SSDLC stages. Correlation engine disabled. Fingerprinting not integrated into ingestion.
- **Correlation**: Correlation engine exists but not invoked in pipeline. No cross-stage correlation (e.g., design-time finding → build-time → runtime event).
- **Finding/Event Model**: No canonical unified model. Findings from SARIF, CVE, CNAPP, micro-pentests use different schemas.
- **Storage**: No persistent finding store with deduplication keys. Findings stored per-run in `app.state.artifacts`.
- **Integrations**: Jira/Confluence connectors may be stubs. No inventory of integration completeness.
- **CLI**: No CLI commands for deduplication/correlation inspection or management.

---

## 2. Feature 1: Deduplication & Correlation Engine

### 2.1 Problem Statement

FixOps ingests findings from multiple sources (scanners, micro-pentests, API, CLI) across SSDLC stages (design, build, deploy, runtime). Current state:
- Same vulnerability reported multiple times (different scanners, different stages)
- No cross-stage correlation (design-time finding → build-time → runtime event)
- Alert fatigue from duplicate findings
- No unified view of vulnerability lifecycle

**Requirements:**
- Deduplicate findings within and across SSDLC stages
- Correlate related findings (same root cause, same component, same vulnerability pattern)
- Support fingerprinting for exact duplicates
- Support fuzzy correlation for related findings
- Maintain audit trail (which findings were deduplicated, why)

### 2.2 Design Goals

- **Reuse existing code**: Activate `CorrelationEngine`, integrate `IdentityResolver` fingerprinting
- **Minimal API changes**: Extend existing ingestion endpoints, add optional deduplication query params
- **Backward compatible**: Deduplication opt-in via feature flag, existing behavior unchanged when disabled
- **Performance**: Sub-millisecond correlation (existing engine designed for this)
- **Storage**: Add finding store with deduplication keys (reuse existing analytics store or add new table)

### 2.3 Canonical Finding/Event Model

**Reuse existing models, extend minimally:**

```python
# Base: core/analytics_models.py Finding
# Extend with:
- fingerprint: str (from IdentityResolver.compute_fingerprint)
- correlation_key: str (from IdentityResolver.compute_correlation_key)
- ssdlc_stage: str (design|build|deploy|runtime)
- source_type: str (scanner|micro_pentest|api|cli)
- source_id: str (scanner name, pentest flow_id, API run_id, CLI session_id)
- first_seen_at: datetime
- last_seen_at: datetime
- deduplication_group_id: Optional[str] (if deduplicated, points to canonical finding)
- correlation_edges: List[str] (finding IDs this finding correlates with)
```

**Event Model (for runtime events):**
- Reuse `Finding` model with `ssdlc_stage="runtime"`
- Add `event_type` (security_incident|exploit_attempt|policy_violation)
- Add `event_timestamp` (when event occurred, not when ingested)

**Unified ingestion:**
- All sources normalize to `Finding` model
- SARIF findings → `Finding` (existing normalization in `apps/api/normalizers.py`)
- CVE records → `Finding` (extend `NormalizedCVEFeed` to produce Findings)
- Micro-pentest results → `Finding` (extend micro-pentest API response)
- CLI scan results → `Finding` (extend CLI scanner)

### 2.4 Deduplication Strategy

**Two-phase approach:**

**Phase 1: Exact Deduplication (Fingerprint-based)**
- Compute fingerprint using `IdentityResolver.compute_fingerprint()` on ingestion
- Check existing findings store for matching fingerprint
- If match found:
  - Update `last_seen_at` on canonical finding
  - Store reference: `deduplication_group_id = canonical_finding.id`
  - Return canonical finding ID (don't create duplicate)
- If no match: create new finding, store fingerprint

**Phase 2: Fuzzy Correlation (Correlation Engine)**
- After exact deduplication, run `CorrelationEngine.correlate_finding()`
- Use existing 5 strategies:
  1. Exact fingerprint (already handled in Phase 1)
  2. Location proximity (same file, nearby lines)
  3. Rule pattern (same rule_id, scanner, severity)
  4. Root cause (same vulnerability category)
  5. Vulnerability taxonomy (same CVE/CWE)
- Store correlation edges: `correlation_edges = [finding_id1, finding_id2, ...]`
- Create correlation graph (nodes = findings, edges = correlations)

**Cross-stage correlation:**
- Design-time finding (SARIF) → Build-time finding (same rule_id, same component)
- Build-time finding → Deploy-time finding (same CVE, same component)
- Deploy-time finding → Runtime event (same component, exploit attempt)

**Implementation:**
- Extend `PipelineOrchestrator.run()` to invoke deduplication after normalization
- Add `DeduplicationService` wrapper around `CorrelationEngine` + `IdentityResolver`
- Store findings in persistent store (extend `AnalyticsStore` or add `FindingStore`)

### 2.5 Correlation Strategy

**Reuse existing `CorrelationEngine` strategies, add cross-stage rules:**

**Existing strategies (from `correlation_engine.py`):**
- `_correlate_by_fingerprint`: Exact match (already used in deduplication)
- `_correlate_by_location`: Same file/location
- `_correlate_by_pattern`: Same rule/scanner/severity
- `_correlate_by_root_cause`: Same vulnerability category
- `_correlate_by_vulnerability`: Same CVE/CWE

**New cross-stage correlation rules:**
- **Design → Build**: Same component + same rule_id → correlate
- **Build → Deploy**: Same component + same CVE → correlate
- **Deploy → Runtime**: Same component + exploit event → correlate
- **Micro-pentest → Finding**: Pentest confirms exploitability → correlate with CVE finding

**Correlation graph:**
- Nodes: Findings (with `ssdlc_stage`, `source_type`)
- Edges: Correlation relationships (with `correlation_type`, `confidence_score`)
- Store in knowledge graph (`new_apps/api/processing/knowledge_graph.py`)

**Noise reduction:**
- Existing `CorrelationEngine` computes `noise_reduction_factor`
- Group correlated findings, show canonical finding + correlated count
- UI: Show "5 related findings" instead of 5 separate entries

### 2.6 API Enhancements / New APIs

**Existing APIs to enhance:**

1. **`POST /inputs/{stage}`** (existing ingestion)
   - Add query param: `?deduplicate=true` (default: false for backward compat)
   - Add query param: `?correlate=true` (default: false)
   - Response: Add `deduplication_result` field if deduplicated
     ```json
     {
       "status": "ok",
       "stage": "sarif",
       "deduplication_result": {
         "canonical_finding_id": "finding-123",
         "was_duplicate": true,
         "correlated_findings": ["finding-456", "finding-789"]
       }
     }
     ```

2. **`POST /pipeline/run`** (existing pipeline)
   - Add query param: `?enable_deduplication=true` (default: false)
   - Response: Add `deduplication_summary` field
     ```json
     {
       "deduplication_summary": {
         "total_findings": 100,
         "unique_findings": 75,
         "duplicates_removed": 25,
         "correlation_groups": 10
       }
     }
     ```

3. **`GET /api/v1/triage`** (existing triage)
   - Response: Add `deduplication_group_id` to each row (if deduplicated)
   - Response: Add `correlated_count` field (how many findings correlate with this)

**New APIs (only if unavoidable):**

1. **`GET /api/v1/findings/{finding_id}/correlations`**
   - Returns correlation graph for a finding
   - Reuse existing `/api/v1/graph` logic, filter by finding_id

2. **`POST /api/v1/findings/deduplicate`**
   - Manual deduplication trigger (admin operation)
   - Request: `{ "finding_ids": ["id1", "id2"], "strategy": "fingerprint" }`
   - Response: Deduplication result

3. **`GET /api/v1/findings/deduplication-stats`**
   - Returns deduplication statistics (total, unique, duplicates, correlation groups)
   - Useful for dashboard/metrics

**No new APIs for CLI ingestion** - CLI uses existing `/inputs/{stage}` endpoints

### 2.7 CLI Changes

**Extend existing CLI commands:**

1. **`fixops scan <path>`** (existing)
   - Add flag: `--deduplicate` (enable deduplication)
   - Add flag: `--correlate` (enable correlation)
   - Output: Show deduplication summary if enabled
     ```
     ✅ Scan complete: 50 findings (25 unique, 25 duplicates removed)
     ```

2. **`fixops monitor`** (existing)
   - Add flag: `--correlate-with-findings` (correlate runtime events with existing findings)
   - Output: Show correlation results

**New CLI commands (optional):**

1. **`fixops findings deduplicate`**
   - Manual deduplication trigger
   - Flags: `--strategy {fingerprint|correlation|all}`, `--dry-run`

2. **`fixops findings correlate <finding_id>`**
   - Show correlation graph for a finding
   - Output: JSON or table format

**Minimal changes**: Reuse existing CLI infrastructure, add flags to existing commands

### 2.8 YAML Overlay Changes

**Extend `config/fixops.overlay.yml`:**

```yaml
modules:
  correlation_engine:
    enabled: true  # Change default from false
    strategies:
      - fingerprint
      - location
      - pattern
      - root_cause
      - vulnerability
    noise_reduction_target: 0.35
    cross_stage_correlation: true  # New
    deduplication:
      enabled: true  # New
      strategy: fingerprint_first  # fingerprint_first|correlation_first|both
      storage:
        provider: analytics_store  # analytics_store|finding_store|both
```

**New overlay keys:**
- `modules.deduplication.enabled` (boolean, default: false)
- `modules.deduplication.strategy` (enum: fingerprint_first, correlation_first, both)
- `modules.correlation_engine.cross_stage_correlation` (boolean, default: false)
- `modules.correlation_engine.deduplication.storage.provider` (enum: analytics_store, finding_store, both)

**Backward compatibility:**
- Default: `deduplication.enabled = false` (existing behavior)
- Default: `correlation_engine.enabled = false` (existing behavior)
- Existing overlays continue to work

### 2.9 Risks & Mitigations

**Risk 1: Performance degradation**
- **Mitigation**: Correlation engine designed for sub-millisecond operations. Use async batch processing. Add feature flag to disable if needed.

**Risk 2: False positives (incorrect deduplication)**
- **Mitigation**: Use high-confidence strategies first (fingerprint > location > pattern). Store audit trail. Allow manual override.

**Risk 3: Storage overhead**
- **Mitigation**: Store fingerprints/correlation keys only, not full finding duplicates. Use existing analytics store (already persisted).

**Risk 4: Backward compatibility**
- **Mitigation**: Feature flag defaults to disabled. Existing APIs unchanged unless opt-in flags provided.

**Risk 5: Cross-stage correlation false positives**
- **Mitigation**: Require high confidence score (>0.8) for cross-stage correlations. Store correlation metadata for audit.

---

## 3. Feature 2: Integrations

### 3.1 Integration Inventory (Stub / Partial / Complete)

**Complete Integrations:**
- **GitHub** (`integrations/github/adapter.py`): Complete adapter, webhook handler, decision engine integration
- **Jenkins** (`integrations/jenkins/adapter.py`): Complete adapter, ingest endpoint, SARIF/SBOM normalization
- **SonarQube** (`integrations/sonarqube/adapter.py`): Complete adapter, issue normalization, decision engine integration
- **PentAGI** (`fixops-enterprise/src/api/v1/micro_pentest.py`): Complete micro-pentest API, flow creation, status polling

**Partial Integrations:**
- **Jira** (`core/connectors.py`): Connector exists, referenced in integrations router (`/api/v1/integrations/{id}/test`), but implementation may be stub (needs verification)
- **Confluence** (`core/connectors.py`): Connector exists, test endpoint available, but implementation may be stub
- **Slack** (`core/connectors.py`): Connector exists, test endpoint available, but full webhook handling unclear

**Stub/Missing Integrations:**
- **GitLab**: No adapter found
- **Azure DevOps**: No adapter found
- **CircleCI**: No adapter found
- **Travis CI**: No adapter found
- **Snyk**: No adapter found
- **Veracode**: No adapter found
- **Checkmarx**: No adapter found
- **Fortify**: No adapter found

**Integration API Status:**
- `/api/v1/integrations` (CRUD): Complete
- `/api/v1/integrations/{id}/test`: Complete (tests Jira/Confluence/Slack connectors)
- `/api/v1/integrations/{id}/sync`: Stub (updates `last_sync_at` but no actual sync logic)

### 3.2 Missing Critical Integrations

**Based on repo intent (DevSecOps Decision Engine):**

**Critical Missing:**
1. **GitLab CI/CD** - Similar to GitHub, needed for GitLab-based workflows
2. **Azure DevOps** - Enterprise CI/CD platform, needed for Azure shops
3. **Snyk** - Popular dependency scanner, should integrate findings
4. **Veracode/Checkmarx/Fortify** - Enterprise SAST/DAST scanners, should integrate findings
5. **Jira/Confluence** - Connectors exist but may be stubs, need verification/completion

**Nice-to-Have:**
- CircleCI, Travis CI (less common)
- Additional scanners (OWASP ZAP, Burp Suite - mentioned in overlay but no adapter)

### 3.3 Design for Completion

**Strategy: Reuse existing adapter pattern**

**Existing pattern (from GitHub/Jenkins/SonarQube):**
1. Adapter class (`GitHubCIAdapter`, `JenkinsCIAdapter`, `SonarQubeAdapter`)
2. Normalize external format to FixOps `Finding` model
3. Call `DecisionEngine.evaluate()` with normalized findings
4. Return FixOps decision + evidence

**For missing integrations:**

1. **GitLab CI/CD**
   - Create `integrations/gitlab/adapter.py`
   - Reuse GitHub adapter pattern (GitLab webhooks similar to GitHub)
   - Endpoint: `/api/v1/cicd/gitlab/webhook` (add to `fixops-enterprise/src/api/v1/cicd.py`)

2. **Azure DevOps**
   - Create `integrations/azure_devops/adapter.py`
   - Normalize Azure DevOps security findings to `Finding` model
   - Endpoint: `/api/v1/cicd/azure-devops/ingest`

3. **Snyk**
   - Create `integrations/snyk/adapter.py`
   - Normalize Snyk test results (JSON) to `Finding` model
   - Endpoint: `/api/v1/scanners/snyk/ingest`

4. **Veracode/Checkmarx/Fortify**
   - Create `integrations/{veracode,checkmarx,fortify}/adapter.py`
   - Normalize SAST/DAST results (XML/JSON) to `Finding` model
   - Endpoint: `/api/v1/scanners/{name}/ingest`

5. **Jira/Confluence completion**
   - Verify `core/connectors.py` implementations
   - If stubs: Complete ticket creation (Jira), page creation (Confluence)
   - Add webhook handlers if needed

**Common adapter interface (optional):**
```python
class IntegrationAdapter:
    def normalize(self, payload: Dict[str, Any]) -> List[Finding]:
        """Normalize external format to FixOps Finding model."""
        pass
    
    def ingest(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Ingest findings and return FixOps decision."""
        findings = self.normalize(payload)
        outcome = self.decision_engine.evaluate({"findings": findings})
        return outcome.to_dict()
```

**No code implementation** - Design only. Implementation follows existing adapter pattern.

### 3.4 API / CLI / YAML Implications

**API Changes:**
- **No changes** - New adapters use existing `/api/v1/cicd/{name}/ingest` pattern
- **New endpoints** (following existing pattern):
  - `POST /api/v1/cicd/gitlab/webhook`
  - `POST /api/v1/cicd/azure-devops/ingest`
  - `POST /api/v1/scanners/snyk/ingest`
  - `POST /api/v1/scanners/{veracode,checkmarx,fortify}/ingest`

**CLI Changes:**
- **No changes** - CLI uses existing API endpoints
- **Optional**: Add `fixops integrations list` command to show integration status

**YAML Overlay Changes:**
- **No changes** - Integrations configured via `/api/v1/integrations` API
- **Optional**: Add `integrations.enabled` list to overlay for default enabled integrations

### 3.5 Risks & Mitigations

**Risk 1: Integration complexity (different formats)**
- **Mitigation**: Reuse existing normalization pattern. Each adapter handles its own format.

**Risk 2: Maintenance burden (many integrations)**
- **Mitigation**: Focus on critical integrations first (GitLab, Azure DevOps, Snyk). Others can be community-contributed.

**Risk 3: Jira/Confluence connector stubs**
- **Mitigation**: Verify implementations first. If stubs, complete them before adding new integrations.

**Risk 4: Breaking changes in external APIs**
- **Mitigation**: Version adapters. Use feature flags to disable problematic integrations.

---

## 4. Non-Goals

**Explicitly excluded from this design:**

1. **Real-time streaming deduplication** - Batch processing only (per ingestion run)
2. **Machine learning-based correlation** - Use existing rule-based correlation engine
3. **Custom correlation strategies** - Use existing 5 strategies, no plugin system
4. **Multi-tenant deduplication** - Deduplication scoped to single tenant/org
5. **Historical finding migration** - Only new findings deduplicated, no backfill
6. **Integration marketplace** - No third-party integration plugins
7. **CLI-based integration testing** - Use API test endpoints only
8. **Integration webhook authentication** - Use existing API key authentication
9. **Cross-org correlation** - Correlation scoped to single org
10. **Deduplication undo** - Once deduplicated, cannot undo (audit trail preserved)

---

## 5. Implementation Readiness Checklist

**Before coding starts, ensure:**

- [ ] Feature flag system operational (`core/flags/` providers working)
- [ ] Analytics store or finding store persistence layer ready
- [ ] `CorrelationEngine` tested in isolation (verify sub-millisecond performance)
- [ ] `IdentityResolver` fingerprinting tested (verify deterministic hashes)
- [ ] Integration adapter pattern documented (for new integrations)
- [ ] Jira/Confluence connector implementations verified (complete or stub?)
- [ ] YAML overlay schema extended (new keys validated)
- [ ] API backward compatibility tested (existing endpoints unchanged when flags disabled)
- [ ] CLI backward compatibility tested (existing commands unchanged)
- [ ] Storage schema designed (finding store table/indexes for fingerprint lookups)
- [ ] Correlation graph storage designed (how to store edges in knowledge graph)
- [ ] Audit trail requirements defined (what to log for deduplication/correlation)

**Dependencies:**
- `CorrelationEngine` (exists, needs activation)
- `IdentityResolver` (exists, needs integration)
- `AnalyticsStore` or new `FindingStore` (storage layer)
- Knowledge graph storage (for correlation edges)
- Feature flag system (exists, operational)

**Blockers:**
- None identified. All required components exist. Design is implementation-ready.
