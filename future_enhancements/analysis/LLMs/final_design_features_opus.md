# FixOps – Final Feature Design

## 1. Current State Summary

### 1.1 Key Findings from Codebase Analysis

**Core Architecture:**
- FastAPI-based API with comprehensive routers for evidence, graph, risk, provenance, pentagi, and pipeline orchestration
- Overlay-based configuration system supporting mode-specific profiles (demo, enterprise)
- Feature flag infrastructure via `core/flags/` with local and LaunchDarkly providers
- SQLite + NetworkX backed provenance graph for lineage tracking
- Modular processing pipeline with SARIF/SBOM/CVE/VEX/CNAPP normalizers

**Data Models (Existing Types):**
- `SarifFinding`: rule_id, message, level, file, line, tool_name
- `SBOMComponent`: name, version, purl, licenses, supplier
- `CVERecordSummary`: cve_id, title, severity, exploited
- `NormalizedSBOM/SARIF/CVEFeed/VEX/CNAPP`: Structured normalized payloads
- `CrosswalkRow`: Links design rows to components, findings, CVEs
- `CorrelationResult` (enterprise): finding_id, correlated_findings, correlation_type, confidence_score

**CLI Commands:**
- `fixops-ci`: Unified CI workflow (sbom, risk, provenance, repro, evidence bundle)
- `fixops-risk score`: Compute risk scores with EPSS/KEV/exposure weights
- `fixops-provenance attest/verify`: SLSA v1 attestation generation/verification
- `fixops-sbom normalize/quality`: SBOM canonicalization and quality metrics
- Main CLI: scan, test, monitor, auth, config

**API Endpoints:**
- `/inputs/{stage}`: File upload ingestion for design, sbom, sarif, cve, vex, cnapp, context
- `/pipeline/run`: Full orchestration with crosswalk, guardrails, compliance evaluation
- `/api/v1/triage`: Triage inbox transformation
- `/api/v1/graph`: Knowledge graph visualization
- `/evidence/*`, `/provenance/*`, `/risk/*`, `/graph/*`: Domain-specific APIs
- `/pentagi/*`: Penetration testing request management

### 1.2 Existing Strengths

- **Robust Normalization Layer**: Handles CycloneDX, SPDX, GitHub dependency snapshots, Syft, Snyk-to-SARIF conversion
- **Provenance Graph**: NetworkX/SQLite hybrid with commit, attestation, component, CVE node types
- **Risk Scoring Engine**: Composite scoring with EPSS, KEV, version lag, exposure, reachability factors
- **Configuration Overlay System**: Deep merge semantics, profile inheritance, feature flags
- **Evidence Hub**: Tamper-evident bundle packaging with encryption, compression, audit logging
- **Compliance Framework Support**: SOC2, ISO27001, PCI_DSS, GDPR control mappings

### 1.3 Existing Gaps

**Deduplication & Correlation:**
- `CorrelationEngine` exists in `fixops-enterprise/src/services/correlation_engine.py` but is **disabled by default**
- No fingerprinting at ingestion time
- No deduplication across pipeline runs or time-series correlation
- No cross-source linking (scanner finding → CVE → component → runtime event)
- VEX suppression applied but not tracked as correlation edge

**Integrations:**
- GitHub, Jenkins, SonarQube adapters: **Complete** (functional decision engine integration)
- Pentagi client: **Complete** (advanced async client with finding extraction)
- Jira/Confluence/Slack/PagerDuty/GitLab: **Stub-level** (types defined, no functional adapters)
- Missing critical integrations: Azure DevOps, AWS Security Hub, Snyk native API, Wiz, Orca, Qualys

---

## 2. Feature 1: Deduplication & Correlation Engine

### 2.1 Problem Statement

Security teams receive redundant alerts across:
- Multiple scanners reporting the same vulnerability
- Same finding appearing across design, build, deploy, and runtime phases
- Duplicate CVE references from SBOM and CVE feeds
- Re-discovery of previously triaged issues

This noise creates alert fatigue, delays remediation prioritization, and obscures true risk posture. The existing enterprise `CorrelationEngine` is disabled and operates only on in-memory findings without persistence or cross-phase linking.

### 2.2 Design Goals

1. **Single Finding Identity**: Assign deterministic fingerprints to findings regardless of source
2. **Cross-Phase Correlation**: Link findings across design → build → deploy → runtime lifecycle
3. **Source Aggregation**: Merge findings from scanners, micro-pentests, API ingestion, CLI
4. **Noise Reduction Target**: ≥35% reduction in duplicate/near-duplicate alerts
5. **Backward Compatibility**: Existing APIs continue to function; new capability is opt-in
6. **Minimal Storage Overhead**: Fingerprint index, not full finding duplication

### 2.3 Canonical Finding/Event Model

Extend existing types rather than creating new schemas:

**Fingerprint Specification:**
```
fingerprint = SHA256(
    normalize(rule_id) +
    normalize(file_path) +
    normalize(cwe_id OR cve_id) +
    normalize(severity_bucket) +
    normalize(tool_class)
)
```

**Normalization Rules:**
- `rule_id`: Lowercase, strip vendor prefix (e.g., "SNYK-" → "")
- `file_path`: Relative path, forward slashes, strip leading `/`
- `severity_bucket`: Map to {critical, high, medium, low, info}
- `tool_class`: Categorize tool (sast, sca, dast, secret, iac, container)

**Canonical Fields (add to existing SarifFinding):**
- `fingerprint: str` — deterministic hash
- `first_seen_at: datetime` — earliest observation
- `last_seen_at: datetime` — most recent observation
- `observation_count: int` — how many times seen
- `phase: Literal["design", "build", "deploy", "runtime"]`
- `correlation_group_id: Optional[str]` — links related findings

**Correlation Edge Types:**
- `SAME_FINGERPRINT`: Exact match across sources
- `SAME_LOCATION`: Same file within 10-line proximity
- `SAME_VULNERABILITY`: Shared CWE or CVE
- `SAME_ROOT_CAUSE`: Pattern-based categorization (injection, auth, crypto, config)
- `SUPPRESSED_BY_VEX`: VEX assertion linkage

### 2.4 Deduplication Strategy

**At Ingestion Time:**
1. Compute fingerprint for each normalized finding
2. Query fingerprint index for existing match
3. If match: update `last_seen_at`, increment `observation_count`, skip re-storage
4. If no match: insert new finding, add to fingerprint index

**Fingerprint Index Storage:**
- SQLite table: `finding_fingerprints(fingerprint TEXT PRIMARY KEY, finding_id TEXT, first_seen TEXT, last_seen TEXT, count INTEGER)`
- Query: O(1) lookup by fingerprint hash

**Configurable Matching Tolerance:**
```yaml
correlation_engine:
  enabled: true
  dedup_strategies:
    - fingerprint       # Exact match
    - location          # Same file ±10 lines
    - vulnerability     # Shared CVE/CWE
  line_tolerance: 10
  ignore_fields:
    - timestamp
    - scan_id
    - tool_version
```

### 2.5 Correlation Strategy

**Multi-Strategy Correlation (reuse existing CorrelationEngine patterns):**

| Strategy | Confidence | Noise Reduction Factor |
|----------|------------|------------------------|
| fingerprint | 0.95 | count / (count + 1) |
| location | 0.80 | count / (count + 2) |
| pattern | 0.70 | count / (count + 3) |
| root_cause | 0.60 | count / (count + 4) |
| vulnerability | 0.90 (CVE) / 0.70 (CWE) | count / (count + 2) |

**Root Cause Categories (reuse from enterprise CorrelationEngine):**
- `input_validation`: injection, xss, traversal, overflow
- `authentication`: auth, login, session, token
- `authorization`: access, privilege, permission, acl
- `crypto`: crypto, ssl, tls, hash, encrypt
- `configuration`: config, default, hardcoded, exposure

**Cross-Phase Linking:**
- Track `phase` field on each finding
- Link findings with same fingerprint across phases
- Expose in API: `/api/v1/findings/{id}/timeline` showing phase progression

### 2.6 API Enhancements / New APIs

**Existing APIs to Enhance:**

| Path | Change |
|------|--------|
| `POST /inputs/{stage}` | Add `fingerprint` field to response; return `duplicate: true` if deduplicated |
| `GET /api/v1/triage` | Add `correlation_group_id`, `observation_count` to each row |
| `GET /api/v1/graph` | Add `CORRELATED_WITH` edge type between finding nodes |
| `POST /pipeline/run` | Return `dedup_stats: {total, deduplicated, reduction_pct}` in response |

**New APIs (only if unavoidable):**

| Path | Method | Purpose |
|------|--------|---------|
| `/api/v1/findings/{fingerprint}/history` | GET | Time-series view of a fingerprint's observations |
| `/api/v1/correlation/groups` | GET | List correlation groups with member counts |
| `/api/v1/correlation/stats` | GET | Noise reduction metrics, dedup ratios |

### 2.7 CLI Changes

**Extend `fixops-ci` with dedup flags:**
```
fixops-ci sbom normalize --dedup --show-duplicates
fixops-ci risk score --correlate --group-by=root_cause
```

**Add `fixops-ci correlation` subcommand:**
```
fixops-ci correlation status           # Show dedup stats
fixops-ci correlation group <id>       # Show members of correlation group
fixops-ci correlation configure        # Interactive config
```

### 2.8 YAML Overlay Changes

**New keys under `modules.correlation_engine`:**
```yaml
modules:
  correlation_engine:
    enabled: true                     # Enable feature (currently false)
    strategies:
      - fingerprint
      - location
      - pattern
      - root_cause
      - vulnerability
    noise_reduction_target: 0.35      # 35% target
    dedup_at_ingestion: true          # Deduplicate during upload
    fingerprint_storage: sqlite       # Options: sqlite, postgres, memory
    line_tolerance: 10
    ignore_fields:
      - timestamp
      - scan_id
    cross_phase_linking: true
```

**Profile overrides:**
```yaml
profiles:
  enterprise:
    modules:
      correlation_engine:
        enabled: true
        fingerprint_storage: postgres
```

### 2.9 Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Fingerprint collision (false positive dedup) | Use SHA256 with sufficient input fields; monitor collision rate metric |
| Performance degradation at scale | Index fingerprints in SQLite; batch correlation in async pipeline |
| Scanner drift changes fingerprints | Exclude volatile fields (tool_version, timestamp) from hash |
| Historical findings not retroactively correlated | Provide migration CLI: `fixops-ci correlation backfill` |
| VEX assertions not reflected in correlation | Treat VEX `not_affected` as SUPPRESSED_BY_VEX edge |
| Cross-phase requires persistent storage | Use existing SQLite evidence storage; add fingerprint table |

---

## 3. Feature 2: Integrations

### 3.1 Integration Inventory (Stub / Partial / Complete)

| Integration | Status | Location | Notes |
|-------------|--------|----------|-------|
| **GitHub CI Adapter** | ✅ Complete | `integrations/github/adapter.py` | Webhook handling, PR comments, decision engine |
| **Jenkins CI Adapter** | ✅ Complete | `integrations/jenkins/adapter.py` | SARIF/SBOM ingestion, signed verdicts |
| **SonarQube Adapter** | ✅ Complete | `integrations/sonarqube/adapter.py` | Issue normalization, decision forwarding |
| **Pentagi Client** | ✅ Complete | `integrations/pentagi_client.py` | Async client, finding extraction, continuous monitoring |
| **Pentagi Service** | ✅ Complete | `integrations/pentagi_service.py` | Service layer wrapper |
| **Jira** | ⚠️ Stub | `core/integration_models.py` (type only) | IntegrationType enum defined; no adapter |
| **Confluence** | ⚠️ Stub | `core/integration_models.py` (type only) | IntegrationType enum defined; no adapter |
| **Slack** | ⚠️ Stub | `core/integration_models.py` (type only) | IntegrationType enum defined; no adapter |
| **PagerDuty** | ⚠️ Stub | `core/integration_models.py` (type only) | IntegrationType enum defined; no adapter |
| **GitLab** | ⚠️ Stub | `core/integration_models.py` (type only) | IntegrationType enum defined; no adapter |
| **Azure DevOps** | ❌ Missing | — | Not referenced in codebase |
| **AWS Security Hub** | ❌ Missing | — | Not referenced in codebase |
| **Snyk Native API** | ⚠️ Partial | SARIF conversion in normalizers | Snyk-to-SARIF fallback; no direct API client |
| **Wiz / Orca / Qualys** | ❌ Missing | — | CNAPP normalizer accepts generic format |

### 3.2 Missing Critical Integrations

Based on repository intent (enterprise security platform) and existing infrastructure:

1. **Jira Adapter** — Policy automation references Jira actions but no functional client
2. **Slack Adapter** — Policy automation references Slack webhooks but no structured adapter
3. **GitLab CI Adapter** — Parallel to GitHub adapter for GitLab-hosted repos
4. **Azure DevOps Adapter** — Enterprise customers on Azure stack
5. **AWS Security Hub** — Export findings to Security Hub for AWS-native workflows
6. **Snyk API Client** — Direct API access vs. file-based SARIF conversion

### 3.3 Design for Completion

**Integration Adapter Pattern (reuse existing adapter structure):**

Each adapter implements:
```
class IntegrationAdapter:
    def __init__(self, config: Dict[str, Any], decision_engine: DecisionEngine)
    async def ingest(self, payload: Mapping[str, Any]) -> Dict[str, Any]
    async def push(self, decision: DecisionOutcome) -> Dict[str, Any]
    def normalize(self, raw: Any) -> List[Dict[str, Any]]
```

**Jira Adapter Completion:**

| Component | Design |
|-----------|--------|
| Auth | Token from `FIXOPS_JIRA_TOKEN` env or overlay `jira.token_env` |
| Create Issue | POST to `/rest/api/3/issue` with mapped fields |
| Update Issue | PUT to `/rest/api/3/issue/{key}` for status transitions |
| Link Findings | Custom field or comment with finding fingerprints |
| Webhook Receive | Endpoint to receive issue update webhooks |

**Slack Adapter Completion:**

| Component | Design |
|-----------|--------|
| Auth | Webhook URL from `policy_automation.slack_webhook_env` |
| Message Format | Block Kit with severity colors, finding summary, action buttons |
| Interactive Actions | Handle button callbacks for triage decisions |
| Thread Updates | Reply in thread when finding status changes |

**GitLab CI Adapter (parallel to GitHub):**

| Component | Design |
|-----------|--------|
| Webhook Events | `merge_request`, `pipeline` events |
| MR Comments | POST to `/api/v4/projects/{id}/merge_requests/{iid}/notes` |
| Pipeline Status | Update external status via CI API |
| Decision Response | Same structure as GitHub adapter |

### 3.4 API / CLI / YAML Implications

**API Additions:**

| Path | Method | Purpose |
|------|--------|---------|
| `/api/v1/integrations` | GET | List configured integrations with status |
| `/api/v1/integrations/{type}/test` | POST | Test connectivity to integration |
| `/api/v1/integrations/{type}/sync` | POST | Force sync (e.g., pull Jira issue states) |

**CLI Additions:**
```
fixops config integrations list
fixops config integrations test jira
fixops config integrations sync gitlab
```

**YAML Additions:**
```yaml
integrations:
  jira:
    enabled: true
    url: ${JIRA_URL}
    project_key: SEC
    token_env: FIXOPS_JIRA_TOKEN
    field_mappings:
      severity: customfield_10001
      fingerprint: customfield_10002
    create_on: guardrail:fail
    
  slack:
    enabled: true
    webhook_env: FIXOPS_SLACK_WEBHOOK
    channel: "#security-alerts"
    notify_on:
      - guardrail:fail
      - guardrail:warn
      
  gitlab:
    enabled: true
    url: ${GITLAB_URL}
    token_env: FIXOPS_GITLAB_TOKEN
    comment_on_mr: true
```

### 3.5 Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Rate limiting from external APIs | Implement exponential backoff; queue outbound requests |
| Token exposure in logs | Mask tokens in structured logging; never log full tokens |
| Integration outage blocks pipeline | Make integrations async/fire-and-forget for non-blocking mode |
| Field mapping complexity for Jira | Provide sensible defaults; allow custom field mapping in overlay |
| Webhook security (spoofed events) | Validate webhook signatures (GitHub HMAC, GitLab token) |
| Stale issue state in Jira | Periodic sync job; webhook receiver for real-time updates |

---

## 4. Non-Goals

The following are explicitly **out of scope** for this design:

1. **Real-time Streaming Ingestion** — Design focuses on batch/API ingestion, not Kafka/Kinesis streams
2. **ML-Based Correlation** — Uses deterministic fingerprinting, not learned embeddings
3. **Automated Remediation Execution** — Tracks decisions, does not auto-patch code
4. **Custom Integration SDK** — Provides adapter pattern, not full plugin marketplace
5. **Mobile App Scanning Integration** — CNAPP normalizer covers generic format, no mobile-specific adapters
6. **SOAR Platform Integration** — Policy automation provides hooks, not full SOAR orchestration
7. **Vulnerability Database Hosting** — Consumes external feeds (EPSS, KEV), does not host CVE database
8. **IDE Plugin Redesign** — Existing VS Code/IntelliJ extensions unchanged
9. **Frontend UI Overhaul** — API changes only; frontend adapts to new response fields
10. **Multi-Tenant Data Isolation Redesign** — Uses existing tenancy module

---

## 5. Implementation Readiness Checklist

Before coding starts, the following must be true:

### 5.1 Deduplication & Correlation Engine

- [ ] `modules.correlation_engine.enabled` can be toggled via feature flag without restart
- [ ] SQLite schema for `finding_fingerprints` table is defined
- [ ] Existing `SarifFinding`, `CVERecordSummary` types accept new optional fields without breaking serialization
- [ ] `CorrelationEngine` class from enterprise is extracted to core (or import path fixed)
- [ ] `/inputs/{stage}` handlers have hook point for fingerprint computation
- [ ] `/pipeline/run` response schema is backward-compatible (new fields optional)
- [ ] Unit tests exist for fingerprint determinism (same input → same hash)
- [ ] Integration test covers dedup across two SARIF uploads with overlapping findings
- [ ] Performance benchmark: fingerprint lookup < 1ms for 100k index size

### 5.2 Integrations

- [ ] `integrations/{jira,slack,gitlab}/adapter.py` files exist with interface stubs
- [ ] Overlay schema validation accepts new `integrations` top-level key
- [ ] Environment variable resolution for tokens tested in CI
- [ ] Mock server available for Jira/Slack/GitLab API testing
- [ ] Policy automation action types extended: `jira_transition`, `slack_thread_update`
- [ ] `/api/v1/integrations` endpoint returns empty list when no integrations configured
- [ ] Rate limiter utility exists in `core/` for reuse across adapters
- [ ] Webhook signature validation helper exists for GitHub/GitLab

### 5.3 Cross-Cutting

- [ ] Feature flag `fixops.feature.correlation_engine` registered in flag provider
- [ ] Telemetry counters added: `fixops_dedup_total`, `fixops_dedup_saved`, `fixops_integration_calls`
- [ ] Documentation PR drafted for new overlay keys
- [ ] Migration path documented for customers with existing pipeline runs
- [ ] Rollback procedure documented (disable flag, drop fingerprint table)

---

*Document generated from multi-perspective architecture review. No code changes implemented.*
